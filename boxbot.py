import json
import logging

from functools import lru_cache

import boto3

from botocore.exceptions import ClientError


@lru_cache
def log():
    return logging.getLogger(__name__)


@lru_cache
def ec2():
    return boto3.client("ec2")


def to_json(thing):
    return json.dumps(thing, sort_keys=True, default=str)


def list_boxes(event, context, client=ec2()):
    body = {"instances": {}}
    try:
        body["instances"] = client.describe_instances()
        return {"statusCode": 200, "body": to_json(body)}
    except ClientError as err:
        log().exception(err)
        return {"statusCode": 500, "body": to_json("oh no")}


def show_box(event, context, client=ec2()):
    return {"statusCode": 501, "body": '"not implemented"'}


def create_box(event, context, client=ec2()):
    return {"statusCode": 501, "body": '"not implemented"'}


def delete_box(event, context, client=ec2()):
    return {"statusCode": 501, "body": '"not implemented"'}
