import typing

from botocore.exceptions import ClientError

import fuzzbucket.cfg as cfg

from . import get_ec2_client, get_vpc_id, list_vpc_boxes, utcnow
from .log import log

DEFAULT_TTL = float(
    typing.cast(
        str,
        cfg.get("FUZZBUCKET_DEFAULT_TTL", default=str(3600 * 4)),
    )
)


def reap_boxes(_, __, ec2_client=None) -> dict[str, list[str]]:
    ec2_client = ec2_client if ec2_client is not None else get_ec2_client()

    reaped_instance_ids = []
    for box in list_vpc_boxes(
        ec2_client,
        get_vpc_id(
            get_ec2_client(),
        ),
    ):
        if box.created_at is None:
            log.warning("skipping box without created_at")
            continue

        ttl = box.ttl
        if ttl is None:
            ttl = DEFAULT_TTL

        expires_at = box.created_at + ttl
        now = utcnow().timestamp()

        log_desc = (
            f"instance_id={box.instance_id!r} "
            + f"name={box.name!r} user={box.user!r} created_at={box.created_at!r} "
            + f"ttl={box.ttl!r} expires_at={expires_at!r}"
        )

        if expires_at > now:
            log.warning(
                f"skipping box that is not stale {log_desc} "
                + f"expires_in={expires_at - now!r}"
            )
            continue

        log.info(f"terminating stale box {log_desc}")

        try:
            ec2_client.terminate_instances(InstanceIds=[box.instance_id])
            reaped_instance_ids.append(box.instance_id)
        except ClientError:
            log.exception(f"failed to terminate stale box {log_desc}")

    return {"reaped_instance_ids": reaped_instance_ids}
