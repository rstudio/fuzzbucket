import base64
import json
import logging
import os
import sys
import time

import boto3

from botocore.exceptions import ClientError

TAGS = {"USER": "boxbot:user", "CREATED_AT": "boxbot:created-at"}


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

    body = {"instances": []}
    try:
        filters = [
            dict(
                Name="instance-state-name",
                Values=["pending", "running", "stopping", "stopped"],
            ),
            dict(Name="tag-key", Values=[TAGS["CREATED_AT"]]),
            dict(Name=f'tag:{TAGS["USER"]}', Values=[user]),
        ]
        body["instances"] = _describe_instances(client, Filters=filters)
        return {"statusCode": 200, "body": _to_json(body)}
    except ClientError:
        log.exception("oh no")
        return {"statusCode": 500, "body": _to_json("oh no")}


def show_box(event, context, client=None):
    return {"statusCode": 501, "body": '"not implemented"'}


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
                    SubnetId="subnet-0c5015feba8daf817",
                    Groups=["sg-0620d67e0cd3cbdc3"],
                )
            ],
            TagSpecifications=[
                dict(
                    ResourceType="instance",
                    Tags=[
                        dict(Key=TAGS["USER"], Value=user),
                        dict(Key=TAGS["CREATED_AT"], Value=str(time.time())),
                    ],
                )
            ],
        )
        return {"statusCode": 200, "body": _to_json(response)}
    except ClientError:
        log.exception("oh no")
        return {"statusCode": 500, "body": _to_json("oh no")}


def delete_box(event, context, client=None):
    return {"statusCode": 501, "body": '"not implemented"'}


def _to_json(thing):
    return json.dumps(thing, sort_keys=True, default=str)


def _describe_instances(client, *args, **kwargs):
    instances = []
    for reservation in client.describe_instances(*args, **kwargs).get(
        "Reservations", []
    ):
        for instance in reservation.get("Instances", []):
            name = "<unknown>"
            for tag in instance.get("Tags", []):
                if tag["Key"] == "Name":
                    name = tag["Value"]
            record = {
                "instance_id": instance["InstanceId"],
                "name": name,
            }
            public_ip = instance.get("PublicIpAddress", None)
            if public_ip is not None:
                record["public_ip"] = public_ip
            instances.append(record)
    return list(sorted(instances, key=lambda i: i["name"]))


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
