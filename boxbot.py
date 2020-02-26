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


def box_please(event, context, client=ec2()):
    body = {"instances": {}}
    try:
        body["instances"] = client.describe_instances()
        return {"statusCode": 200, "body": to_json(body)}
    except ClientError as err:
        log().exception(err)
        return {"statusCode": 500, "body": to_json("oh no")}
