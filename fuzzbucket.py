import base64
import datetime
import enum
import json
import logging
import os
import time
import urllib.request

import boto3

from botocore.exceptions import ClientError

from image_aliases import image_aliases


class Tags(enum.Enum):
    user = "fuzzbucket:user"
    created_at = "fuzzbucket:created-at"
    image_alias = "fuzzbucket:image-alias"


class Box:
    def __init__(self):
        self.created_at = None
        self.image_alias = None
        self.image_id = None
        self.instance_id = None
        self.instance_type = None
        self.name = None
        self.public_dns_name = None
        self.public_ip = None

    def as_json(self):
        return dict(
            [
                (key, getattr(self, key))
                for key in (list(self.__dict__.keys()) + ["age"])
                if getattr(self, key) is not None
            ]
        )

    @property
    def age(self):
        if not self.created_at:
            return "?"
        delta = datetime.datetime.utcnow() - datetime.datetime.fromtimestamp(
            float(self.created_at)
        )
        hours, remainder = divmod(delta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{delta.days}d{hours}h{minutes}m{seconds}s"

    @classmethod
    def from_ec2_dict(cls, instance):
        box = cls()
        box.instance_id = instance["InstanceId"]
        box.instance_type = instance["InstanceType"]
        box.image_id = instance["ImageId"]
        box.public_dns_name = (
            instance["PublicDnsName"] if instance["PublicDnsName"] != "" else None
        )
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


ROOT_LOG = logging.getLogger()
log = ROOT_LOG.getChild("fuzzbucket")
log.setLevel(getattr(logging, os.environ.get("LOG_LEVEL", "info").upper()))


def list_boxes(event, context, client=None, env=None):
    try:
        client = client if client is not None else boto3.client("ec2")
        env = env if env is not None else dict(os.environ)
        vpc_id = env["CF_VPC"]
        log.debug(f"handling event={event!r}")
        user = _extract_user(event)
        if user is None:
            return {
                "statusCode": 403,
                "body": _to_json("no user found"),
            }

        return {
            "statusCode": 200,
            "body": _to_json({"boxes": _list_user_boxes(client, user, vpc_id)}),
        }
    except ClientError:
        log.exception("oh no boto3")
        return {"statusCode": 500, "body": _to_json("oh no boto3")}
    except Exception:
        log.exception("oh no")
        return {"statusCode": 500, "body": _to_json("oh no")}


def create_box(event, context, client=None, env=None):
    try:
        client = client if client is not None else boto3.client("ec2")
        env = env if env is not None else dict(os.environ)
        vpc_id = env["CF_VPC"]
        log.debug(f"handling event={event!r}")
        user = _extract_user(event)
        if user is None:
            return {
                "statusCode": 403,
                "body": _to_json("no user found"),
            }

        body = json.loads(event.get("body", "{}"))
        ami = body.get("ami")
        if ami is not None:
            image_alias = "custom"
        else:
            image_alias = body.get("image_alias", "ubuntu18")
            ami = _resolve_ami_alias(image_alias, env)
        if ami is None:
            return {
                "statusCode": 400,
                "body": _to_json(f"unknown image_alias={image_alias}"),
            }

        existing_keys = client.describe_key_pairs(
            Filters=[dict(Name="key-name", Values=[user])]
        )
        if len(existing_keys["KeyPairs"]) == 0:
            key_material = _fetch_first_github_key(user)
            if key_material.strip() == "":
                return {
                    "statusCode": 400,
                    "body": _to_json(f"could not fetch public key for user={user}"),
                }

            client.import_key_pair(
                KeyName=user, PublicKeyMaterial=key_material.encode("utf-8")
            )
            log.debug(f"imported public key for user={user}")

        name = body.get("name")
        if name is None:
            name = f"fuzzbucket-{user}-{image_alias}"

        for instance in _list_user_boxes(client, user, vpc_id):
            if instance.name == name:
                return {"statusCode": 409, "body": _to_json({"boxes": [instance]})}

        network_interface = dict(
            DeviceIndex=0, AssociatePublicIpAddress=True, DeleteOnTermination=True,
        )

        subnet_id = env.get("CF_PublicSubnet", None)
        if subnet_id is not None:
            network_interface["SubnetId"] = subnet_id
        security_groups = [
            sg.strip()
            for sg in env.get("CF_FuzzbucketDefaultSecurityGroup", "").split(" ")
        ]

        if body.get("connect") is not None:
            security_groups += [
                sg.strip()
                for sg in env.get("CF_FuzzbucketConnectSecurityGroup", "").split(" ")
            ]
        if len(security_groups) > 0:
            network_interface["Groups"] = security_groups

        response = client.run_instances(
            ImageId=ami,
            InstanceType=body.get(
                "instance_type",
                env.get("FUZZBUCKET_DEFAULT_INSTANCE_TYPE", "t3.small"),
            ),
            KeyName=user,
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[network_interface],
            TagSpecifications=[
                dict(
                    ResourceType="instance",
                    Tags=[
                        dict(Key="Name", Value=name),
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
                    "boxes": [
                        Box.from_ec2_dict(inst)
                        for inst in response.get("Instances", [])
                    ]
                }
            ),
        }
    except ClientError:
        log.exception("oh no boto3")
        return {"statusCode": 500, "body": _to_json("oh no boto3")}
    except FileNotFoundError:
        log.exception("oh no file")
        return {"statusCode": 500, "body": _to_json("oh no file")}
    except Exception:
        log.exception("oh no")
        return {"statusCode": 500, "body": _to_json("oh no")}


def reboot_box(event, context, client=None, env=None):
    try:
        client = client if client is not None else boto3.client("ec2")
        env = env if env is not None else dict(os.environ)
        vpc_id = env["CF_VPC"]
        log.debug(f"handling event={event!r}")
        user = _extract_user(event)
        if user is None:
            return {
                "statusCode": 403,
                "body": _to_json("no user found"),
            }
        instance_id = event.get("pathParameters", {}).get("id", None)
        if instance_id is None:
            return {"statusCode": 400, "body": _to_json("missing id")}
        if instance_id not in [
            b.instance_id for b in _list_user_boxes(client, user, vpc_id)
        ]:
            return {"statusCode": 403, "body": _to_json("no touching")}
        client.reboot_instances(InstanceIds=[instance_id])
        return {"statusCode": 204, "body": ""}
    except ClientError:
        log.exception("oh no boto3")
        return {"statusCode": 500, "body": _to_json("oh no boto3")}
    except Exception:
        log.exception("oh no")
        return {"statusCode": 500, "body": _to_json("oh no")}


def delete_box(event, context, client=None, env=None):
    try:
        client = client if client is not None else boto3.client("ec2")
        env = env if env is not None else dict(os.environ)
        vpc_id = env["CF_VPC"]
        log.debug(f"handling event={event!r}")
        user = _extract_user(event)
        if user is None:
            return {
                "statusCode": 403,
                "body": _to_json("no user found"),
            }
        instance_id = event.get("pathParameters", {}).get("id", None)
        if instance_id is None:
            return {"statusCode": 400, "body": _to_json("missing id")}
        if instance_id not in [
            b.instance_id for b in _list_user_boxes(client, user, vpc_id)
        ]:
            return {"statusCode": 403, "body": _to_json("no touching")}
        client.terminate_instances(InstanceIds=[instance_id])
        return {"statusCode": 204, "body": ""}
    except ClientError:
        log.exception("oh no boto3")
        return {"statusCode": 500, "body": _to_json("oh no boto3")}
    except Exception:
        log.exception("oh no")
        return {"statusCode": 500, "body": _to_json("oh no")}


def _to_json(thing):
    return json.dumps(thing, sort_keys=True, default=_as_json)


def _as_json(thing):
    if hasattr(thing, "as_json") and callable(thing.as_json):
        return thing.as_json()
    if hasattr(thing, "__dict__"):
        return thing.__dict__
    return str(thing)


def _list_user_boxes(client, user, vpc_id):
    filters = DEFAULT_FILTERS + [
        dict(Name=f"tag:{Tags.user.value}", Values=[user]),
        dict(Name="vpc-id", Values=[vpc_id]),
    ]
    boxes = []
    for reservation in client.describe_instances(Filters=filters).get(
        "Reservations", []
    ):
        boxes += [Box.from_ec2_dict(inst) for inst in reservation.get("Instances", [])]
    return list(sorted(boxes, key=lambda i: i.name))


def _resolve_ami_alias(image_alias, env):
    return image_aliases.get(image_alias, None)


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


def _fetch_first_github_key(user):
    with urllib.request.urlopen(f"https://github.com/{user}.keys") as response:
        return response.read().decode("utf-8").split("\n")[0].strip()


def _q(event, key, default=None):
    if event is None:
        return default
    qs = event.get("queryStringParameters", {})
    if qs is None:
        return default
    return qs.get(key, default)
