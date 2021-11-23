import os

from . import list_vpc_boxes, log, get_ec2_client, utcnow


def reap_boxes(event: dict, context: dict, ec2_client=None, env: dict = None) -> dict:
    ec2_client = ec2_client if ec2_client is not None else get_ec2_client()
    env = env if env is not None else dict(os.environ)
    reaped_instance_ids = []
    for box in list_vpc_boxes(ec2_client, env["CF_VPC"]):
        if box.created_at is None:
            log.warning("skipping box without created_at")
            continue
        ttl = box.ttl
        if ttl is None:
            ttl = float(env.get("FUZZBUCKET_DEFAULT_TTL", str(3600 * 4)))
        expires_at = box.created_at + ttl
        now = utcnow().timestamp()
        if expires_at > now:
            log.warning(
                f"skipping box that is not stale instance_id={box.instance_id!r} "
                + f"created_at={box.created_at!r} ttl={box.ttl!r} "
                + f"expires_at={expires_at!r} expires_in={expires_at - now!r}"
            )
            continue
        log.info(
            f"terminating stale box instance_id={box.instance_id!r} name={box.name!r} "
            + f"created_at={box.created_at!r} user={box.user!r}"
        )
        ec2_client.terminate_instances(InstanceIds=[box.instance_id])
        reaped_instance_ids.append(box.instance_id)
    return {"reaped_instance_ids": reaped_instance_ids}
