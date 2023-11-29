import functools
import os
import random
import typing

import boto3
import botocore.exceptions
from flask_dance.contrib.github import github

from . import box, cfg, tags
from .log import log

DEFAULT_FILTERS: tuple[tuple[tuple[str, str | list[str]], ...], ...] = (
    (
        ("Name", "instance-state-name"),
        ("Values", ["pending", "running", "stopping", "stopped"]),
    ),
    (
        ("Name", "tag-key"),
        ("Values", [tags.Tags.created_at.value]),
    ),
    (
        ("Name", "tag-key"),
        ("Values", [tags.Tags.image_alias.value]),
    ),
)


@functools.cache
def get_dynamodb():
    if os.getenv("IS_OFFLINE") is not None:
        return boto3.resource(
            "dynamodb",
            region_name="localhost",
            endpoint_url="http://localhost:8000",
        )

    return boto3.resource("dynamodb")


@functools.cache
def get_ec2_client():
    return boto3.client("ec2")


@functools.cache
def get_vpc_id(ec2_client, env: dict[str, str] | None = None) -> str | None:
    value = typing.cast(
        str,
        cfg.get(
            "FUZZBUCKET_DEFAULT_VPC",
            default="NOTSET",
            env=env,
        ),
    )

    if value.startswith("vpc-"):
        return value

    candidate_vpcs = ec2_client.describe_vpcs(
        Filters=[
            dict(Name="tag:Name", Values=[value]),
        ]
    ).get("Vpcs", [])

    if len(candidate_vpcs) == 0:
        return None

    return candidate_vpcs[0]["VpcId"]


def list_vpc_boxes(ec2_client, vpc_id):
    return list_boxes_filtered(
        ec2_client,
        [dict(f) for f in DEFAULT_FILTERS] + [dict(Name="vpc-id", Values=[vpc_id])],
    )


def list_boxes_filtered(ec2_client, filters):
    boxes = []
    for reservation in ec2_client.describe_instances(Filters=filters).get(
        "Reservations", []
    ):
        boxes += [
            box.Box.from_ec2_dict(inst) for inst in reservation.get("Instances", [])
        ]

    return list(sorted(boxes, key=lambda i: i.name))


def list_user_boxes(ec2_client, user, vpc_id):
    return list_boxes_filtered(
        ec2_client,
        [dict(f) for f in DEFAULT_FILTERS]
        + [
            dict(Name=f"tag:{tags.Tags.user.value}", Values=[user]),
            dict(Name="vpc-id", Values=[vpc_id]),
        ],
    )


def resolve_ami_alias(image_alias: str, ddb: typing.Any = None) -> str | None:
    ddb = ddb if ddb is not None else get_dynamodb()

    try:
        resp = ddb.Table(cfg.IMAGE_ALIASES_TABLE).get_item(Key=dict(alias=image_alias))

        return typing.cast(dict, resp.get("Item", {})).get("ami")
    except Exception:
        log.exception("oh no boto3")

        return None


def resolve_security_groups(security_groups: list[str]) -> list[str]:
    log.debug(f"resolving security groups={security_groups!r}")

    return [
        sg
        for sg in [resolve_security_group(sg_alias) for sg_alias in security_groups]
        if sg != ""
    ]


@functools.cache
def resolve_security_group(security_group: str) -> str:
    log.debug(f"resolving security group={security_group!r}")

    if security_group.startswith("sg-"):
        return security_group

    candidate_groups = (
        get_ec2_client()
        .describe_security_groups(
            Filters=[
                dict(Name="group-name", Values=[security_group]),  # type: ignore
            ],
        )
        .get("SecurityGroups")
    )

    if not candidate_groups:
        return security_group

    return candidate_groups[0].get("GroupId", "")


def find_subnet() -> str | None:
    default_subnets = cfg.getlist("FUZZBUCKET_DEFAULT_SUBNETS")

    if not cfg.getbool("FUZZBUCKET_AUTO_SUBNET"):
        return (
            resolve_subnet(random.choice(default_subnets)) if default_subnets else None
        )

    candidate_subnets = (
        get_ec2_client()
        .describe_subnets(
            Filters=[  # type: ignore
                dict(
                    Name="vpc-id",
                    Values=[
                        get_vpc_id(get_ec2_client()),
                    ],
                ),
                dict(
                    Name="state",
                    Values=["available"],
                ),
            ]
        )
        .get("Subnets", [])
    )

    if len(candidate_subnets) == 0:
        return (
            resolve_subnet(random.choice(default_subnets)) if default_subnets else None
        )

    candidate_subnets.sort(key=lambda s: s["AvailableIpAddressCount"])  # type: ignore

    return typing.cast(dict, candidate_subnets[-1])["SubnetId"]


@functools.cache
def resolve_subnet(subnet_id_or_name: str) -> str | None:
    log.debug(f"resolving subnet id={subnet_id_or_name!r}")

    return (
        get_ec2_client()
        .describe_security_groups(
            Filters=[
                dict(Name="tag:Name", Values=[subnet_id_or_name]),  # type: ignore
            ],
        )
        .get("Subnets", [{"SubnetId": subnet_id_or_name}])[0]
        .get("SubnetId")
    )


def find_matching_ec2_key_pair(user: str) -> typing.Optional[dict]:
    low_user = str(user).lower()

    for key_pair in get_ec2_client().describe_key_pairs().get("KeyPairs", []):
        key_pair = typing.cast(dict, key_pair)

        if key_pair["KeyName"].lower() == low_user:
            return key_pair

    return None


def find_matching_ec2_key_pairs(prefix: str) -> typing.List[dict]:
    low_prefix = str(prefix).lower()
    ret = []

    for key_pair in get_ec2_client().describe_key_pairs().get("KeyPairs", []):
        key_pair = typing.cast(dict, key_pair)

        key_name = key_pair["KeyName"].lower()
        if key_name == low_prefix or key_name.startswith(low_prefix + "-"):
            ret.append(key_pair)

    return ret


def fetch_first_compatible_github_key(user: str) -> str:
    try:
        for key in github.get("/user/keys").json():
            stripped_key = key.get("key", "").strip()
            if is_ec2_compatible_key(stripped_key):
                return stripped_key

        log.warning(f"no compatible ssh key could be found in github for user={user!r}")

        return ""
    except Exception as exc:
        log.warning(
            f"error while fetching first compatible github key for user={user!r} err={exc}"
        )

        return ""


def is_ec2_compatible_key(key_material: str) -> bool:
    return key_material.startswith("ssh-rsa") or key_material.startswith("ssh-ed25519")
