import base64
import enum
import json
import logging
import os
import sys
import time

import boto3

from botocore.exceptions import ClientError


class Tags(enum.Enum):
    user = "boxbot:user"
    created_at = "boxbot:created-at"
    image_alias = "boxbot:image-alias"


class Box:
    def __init__(self):
        self.instance_id = ""
        self.name = ""
        self.created_at = ""
        self.image_alias = ""
        self.public_ip = None

    @classmethod
    def from_ec2_dict(cls, instance):
        box = cls()
        box.instance_id = instance["InstanceId"]
        for tag in instance.get("Tags", []):
            if tag["Key"] == "Name":
                box.name = tag["Value"]
            elif tag["Key"] == Tags.created_at.value:
                box.created_at = tag["Value"]
            elif tag["Key"] == Tags.image_alias.value:
                box.image_alias = tag["Value"]

        box.public_ip = instance.get("PublicIpAddress", None)
        return box


DEFAULT_FILTERS = [
    dict(
        Name="instance-state-name",
        Values=["pending", "running", "stopping", "stopped"],
    ),
    dict(Name="tag-key", Values=[Tags.created_at.value]),
    dict(Name="tag-key", Values=[Tags.image_alias.value]),
]


log = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    style="{",
    format="name={name!r} level={levelname!r} time={asctime!r} msg={message!r}",
    level=getattr(logging, os.environ.get("LOG_LEVEL", "info").upper()),
)


def list_boxes(event, context, client=None):
    client = client if client is not None else boto3.client("ec2")
    user = _extract_user(event)
    if user is None:
        return {
            "statusCode": 403,
            "body": _to_json("no user found"),
        }

    try:
        return {
            "statusCode": 200,
            "body": _to_json({"instances": _list_user_boxes(client, user)}),
        }
    except ClientError:
        log.exception("oh no")
        return {"statusCode": 500, "body": _to_json("oh no")}


def create_box(event, context, client=None):
    client = client if client is not None else boto3.client("ec2")
    user = _extract_user(event)
    if user is None:
        return {
            "statusCode": 403,
            "body": _to_json("no user found"),
        }

    image_alias = _q(event, "image_alias", "ubuntu18")
    ami = _resolve_ami_alias(image_alias, None)
    if ami is None:
        return {
            "statusCode": 400,
            "body": _to_json(f"unknown image_alias={image_alias}"),
        }

    for instance in _list_user_boxes(client, user):
        if instance.image_alias == image_alias:
            return {"statusCode": 409, "body": _to_json({"instances": [instance]})}

    try:
        response = client.run_instances(
            # FIXME: un-hardcodify
            ImageId=ami,
            InstanceType="t3.small",
            KeyName="connect",
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[
                dict(
                    DeviceIndex=0,
                    AssociatePublicIpAddress=True,
                    DeleteOnTermination=True,
                    # SubnetId="subnet-0c5015feba8daf817",
                    # Groups=["sg-0620d67e0cd3cbdc3"],
                )
            ],
            TagSpecifications=[
                dict(
                    ResourceType="instance",
                    Tags=[
                        dict(Key="Name", Value=f"boxbot-{user}-{image_alias}"),
                        dict(Key=Tags.user.value, Value=user),
                        dict(Key=Tags.created_at.value, Value=str(time.time())),
                        dict(Key=Tags.image_alias.value, Value=image_alias),
                    ],
                )
            ],
        )
        return {
            "statusCode": 200,
            "body": _to_json(
                {
                    "instances": [
                        Box.from_ec2_dict(inst)
                        for inst in response.get("Instances", [])
                    ]
                }
            ),
        }
    except ClientError:
        log.exception("oh no")
        return {"statusCode": 500, "body": _to_json("oh no")}


def delete_box(event, context, client=None):
    client = client if client is not None else boto3.client("ec2")
    user = _extract_user(event)
    if user is None:
        return {
            "statusCode": 403,
            "body": _to_json("no user found"),
        }
    instance_id = event.get("pathParameters", {}).get("id", None)
    if instance_id is None:
        return {"statusCode": 400, "body": _to_json("missing id")}
    try:
        client.terminate_instances(InstanceIds=[instance_id])
        return {"statusCode": 204, "body": ""}
    except ClientError:
        log.exception("oh no")
        return {"statusCode": 500, "body": _to_json("oh no")}


def _to_json(thing):
    return json.dumps(thing, sort_keys=True, default=_as_json)


def _as_json(thing):
    if hasattr(thing, "__dict__"):
        return thing.__dict__
    return str(thing)


def _list_user_boxes(client, user):
    filters = DEFAULT_FILTERS + [
        dict(Name=f"tag:{Tags.user.value}", Values=[user]),
    ]
    instances = []
    for reservation in client.describe_instances(Filters=filters).get(
        "Reservations", []
    ):
        instances += [
            Box.from_ec2_dict(inst) for inst in reservation.get("Instances", [])
        ]
    return list(sorted(instances, key=lambda i: i.name))


def _resolve_ami_alias(image_alias, default=None):
    # TODO: dynamically?
    return {"ubuntu18": "ami-046842448f9e74e7d"}.get(image_alias, default)


def _extract_user(event):
    auth_header = None
    if "Authorization" in event.get("headers", {}):
        auth_header = event["headers"]["Authorization"]
    if "authorization" in event.get("headers", {}):
        auth_header = event["headers"]["authorization"]

    if auth_header is not None:
        b64_token = auth_header.split(" ")[-1]
        return base64.b64decode(b64_token).decode("utf-8").split(":")[0]

    return _q(event, "user")


def _q(event, key, default=None):
    if event is None:
        return default
    qs = event.get("queryStringParameters", {})
    if qs is None:
        return default
    return qs.get(key, default)
