import json
import logging
import os
import sys

import boto3

from botocore.exceptions import ClientError


log = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    style="{",
    format="name={name!r} level={levelname!r} time={asctime!r} msg={message!r}",
    level=getattr(logging, os.environ.get("LOG_LEVEL", "info").upper()),
)


def list_boxes(event, context, client=None):
    log.debug(f"received event={_to_json(event)}")
    client = boto3.client("ec2") if client is None else client
    body = {"instances": {}}
    try:
        filters = ()
        user = _q(event, "user")
        if user is not None:
            filters = [{"Name": "tag:boxbot:user", "Values": [user]}]
        body["instances"] = _describe_instances(client, Filters=filters)
        return {"statusCode": 200, "body": _to_json(body)}
    except ClientError:
        log.exception("oh no")
        return {"statusCode": 500, "body": _to_json("oh no")}


def show_box(event, context, client=None):
    return {"statusCode": 501, "body": '"not implemented"'}


def create_box(event, context, client=None):
    return {"statusCode": 501, "body": '"not implemented"'}


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


def _q(event, key, default=None):
    if event is None:
        return default
    qs = event.get("queryStringParameters", {})
    if qs is None:
        return default
    return qs.get(key, default)


log.info("boxbot is alive")
