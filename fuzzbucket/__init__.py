import functools
import logging
import os
import typing

import boto3

from .tags import Tags


ROOT_LOG = logging.getLogger()
LOG_LEVEL = os.environ.get("FUZZBUCKET_LOG_LEVEL", "info").upper()
log = ROOT_LOG.getChild("fuzzbucket")
log.setLevel(getattr(logging, LOG_LEVEL))


NoneString = typing.Optional[str]


def deferred_app(
    environ: typing.Dict[str, str], start_response: typing.Callable
) -> typing.Iterable[str]:
    from .app import app

    return app(environ, start_response)


def deferred_reap_boxes(event, context):
    from .reaper import reap_boxes

    return reap_boxes(event, context)


@functools.lru_cache(maxsize=2)
def get_ec2_client():
    return boto3.client("ec2")


@functools.lru_cache(maxsize=2)
def get_dynamodb():
    if os.getenv("IS_OFFLINE") is not None:
        return boto3.resource(
            "dynamodb", region_name="localhost", endpoint_url="http://localhost:8000",
        )
    return boto3.resource("dynamodb")


DEFAULT_FILTERS = [
    dict(
        Name="instance-state-name",
        Values=["pending", "running", "stopping", "stopped"],
    ),
    dict(Name="tag-key", Values=[Tags.created_at.value]),
    dict(Name="tag-key", Values=[Tags.image_alias.value]),
]


def list_vpc_boxes(ec2_client, vpc_id):
    return list_boxes_filtered(
        ec2_client, DEFAULT_FILTERS + [dict(Name="vpc-id", Values=[vpc_id])]
    )


def list_boxes_filtered(ec2_client, filters):
    from .box import Box

    boxes = []
    for reservation in ec2_client.describe_instances(Filters=filters).get(
        "Reservations", []
    ):
        boxes += [Box.from_ec2_dict(inst) for inst in reservation.get("Instances", [])]
    return list(sorted(boxes, key=lambda i: i.name))


def list_user_boxes(ec2_client, user, vpc_id):
    return list_boxes_filtered(
        ec2_client,
        DEFAULT_FILTERS
        + [
            dict(Name=f"tag:{Tags.user.value}", Values=[user]),
            dict(Name="vpc-id", Values=[vpc_id]),
        ],
    )
