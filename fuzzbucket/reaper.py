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

        log_desc = dict(
            instance_id=box.instance_id,
            box_name=box.name,
            user=box.user,
            created_at=box.created_at,
            ttl=box.ttl,
            expires_at=expires_at,
        )

        if expires_at > now:
            log.warning(
                "skipping box that is not stale",
                extra=(log_desc | dict(expires_in=expires_at - now)),
            )
            continue

        log.info("terminating stale box", extra=log_desc)

        try:
            ec2_client.terminate_instances(InstanceIds=[box.instance_id])
            reaped_instance_ids.append(box.instance_id)
        except ClientError:
            log.exception("failed to terminate stale box", extra=log_desc)

    return {"reaped_instance_ids": reaped_instance_ids}
