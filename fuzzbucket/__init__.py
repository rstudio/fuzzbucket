import datetime
import functools
import os
import typing

import boto3
from flask.json.provider import DefaultJSONProvider

import fuzzbucket.cfg as cfg

from .tags import Tags


def deferred_app(
    environ: dict[str, str], start_response: typing.Callable
) -> typing.Iterable[str]:
    from .app import app

    return app(environ, start_response)


def deferred_reap_boxes(event, context):
    from .reaper import reap_boxes

    return reap_boxes(event, context)


@functools.cache
def get_ec2_client():
    return boto3.client("ec2")


@functools.cache
def get_dynamodb():
    if os.getenv("IS_OFFLINE") is not None:
        return boto3.resource(
            "dynamodb",
            region_name="localhost",
            endpoint_url="http://localhost:8000",
        )

    return boto3.resource("dynamodb")


DEFAULT_FILTERS: tuple[tuple[tuple[str, str | list[str]], ...], ...] = (
    (
        ("Name", "instance-state-name"),
        ("Values", ["pending", "running", "stopping", "stopped"]),
    ),
    (
        ("Name", "tag-key"),
        ("Values", [Tags.created_at.value]),
    ),
    (
        ("Name", "tag-key"),
        ("Values", [Tags.image_alias.value]),
    ),
)


class AsJSONProvider(DefaultJSONProvider):
    @staticmethod
    def default(o: typing.Any) -> typing.Any:
        if hasattr(o, "as_json") and callable(o.as_json):
            return o.as_json()

        if hasattr(o, "__dict__"):
            return o.__dict__

        return DefaultJSONProvider.default(o)  # pragma: no cover


@functools.cache
def get_vpc_id(ec2_client) -> str:
    value = cfg.vpc_id()

    if value.startswith("vpc-"):
        return value

    candidate_vpcs = ec2_client.describe_vpcs(
        Filters=[
            dict(Name="tag:Name", Values=[value]),
        ]
    ).get("Vpcs", [])

    if len(candidate_vpcs) == 0:
        return value

    return candidate_vpcs[0]["VpcId"]


def list_vpc_boxes(ec2_client, vpc_id):
    return list_boxes_filtered(
        ec2_client,
        [dict(f) for f in DEFAULT_FILTERS] + [dict(Name="vpc-id", Values=[vpc_id])],
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
        [dict(f) for f in DEFAULT_FILTERS]
        + [
            dict(Name=f"tag:{Tags.user.value}", Values=[user]),
            dict(Name="vpc-id", Values=[vpc_id]),
        ],
    )


def utcnow() -> datetime.datetime:
    return datetime.datetime.utcnow()
