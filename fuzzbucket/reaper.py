from botocore.exceptions import ClientError

from . import aws, cfg, datetime_ext
from .log import log


def reap_boxes(_, __, ec2_client=None) -> dict[str, list[str]]:
    ec2_client = ec2_client if ec2_client is not None else aws.get_ec2_client()

    reaped_instance_ids = []
    for box in aws.list_vpc_boxes(ec2_client, aws.get_vpc_id(ec2_client)):
        if box.created_at is None:
            log.warning("skipping box without created_at")
            continue

        ttl = box.ttl
        if ttl is None:
            ttl = cfg.DEFAULT_TTL

        expires_at = box.created_at + ttl
        now = datetime_ext.utcnow().timestamp()

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
