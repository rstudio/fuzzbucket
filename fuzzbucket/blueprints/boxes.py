import typing

import flask

from .. import auth, aws, box, cfg, datetime_ext, tags
from ..log import log

bp = flask.Blueprint("boxes", __name__)


@bp.route("/", methods=("GET",), strict_slashes=False)
def list_boxes():
    if not auth.is_fully_authd():
        return auth.auth_403()

    log.debug(f"handling list_boxes for user={flask.request.remote_user!r}")

    return (
        flask.jsonify(
            boxes=aws.list_user_boxes(
                aws.get_ec2_client(),
                flask.request.remote_user,
                aws.get_vpc_id(aws.get_ec2_client()),
            ),
            you=flask.request.remote_user,
        ),
        200,
    )


@bp.route("/", methods=("POST",), strict_slashes=False)
def create_box():
    if not auth.is_fully_authd():
        return auth.auth_403()

    log.debug(f"handling create_box for user={flask.session['user']!r}")

    if not flask.request.is_json:
        return flask.jsonify(error="request is not json"), 400

    assert flask.request.json is not None

    ami = flask.request.json.get("ami")
    if ami is not None:
        image_alias = "custom"
    else:
        image_alias = flask.request.json.get("image_alias", "ubuntu18")
        ami = aws.resolve_ami_alias(image_alias)

    if ami is None:
        return flask.jsonify(error=f"unknown image_alias={image_alias}"), 400

    key_alias = flask.request.json.get("key_alias", "default")

    full_key_alias = flask.session["user"]
    if str(key_alias).lower() != "default":
        full_key_alias = f"{flask.session['user']}-{key_alias}"

    matching_key = aws.find_matching_ec2_key_pair(full_key_alias)
    username = flask.session["user"]
    resolved_key_name = (matching_key or {}).get("KeyName")

    if matching_key is None and cfg.AUTH_PROVIDER == "github-oauth":
        if full_key_alias != flask.session["user"]:
            return (
                flask.jsonify(
                    error=f"key with alias {key_alias} does not exist",
                    you=flask.request.remote_user,
                ),
                400,
            )

        key_material = aws.fetch_first_compatible_github_key(flask.session["user"])
        username = flask.session["user"]

        if key_material == "":
            return (
                flask.jsonify(
                    error=f"could not fetch compatible public key for user={username!r}"
                ),
                400,
            )

        aws.get_ec2_client().import_key_pair(
            KeyName=username, PublicKeyMaterial=key_material.encode("utf-8")
        )
        resolved_key_name = username
        log.debug(f"imported compatible public key for user={username!r}")

    name = flask.request.json.get("name")
    if str(name or "").strip() == "":
        name = f"fuzzbucket-{username}-{image_alias}"

    ttl = flask.request.json.get("ttl")
    if str(ttl or "").strip() == "":
        ttl = str(3600 * 4)

    # NOTE: the `ttl` value must by a string for use as a tag
    # value, and it's also nice of us to normalize it to an
    # integer.
    ttl = str(int(ttl))

    for instance in aws.list_user_boxes(
        aws.get_ec2_client(), username, aws.get_vpc_id(aws.get_ec2_client())
    ):
        if instance.name == name:
            return flask.jsonify(boxes=[instance], you=username), 409

    network_interface: dict[str, int | bool | str | list[str]] = dict(
        DeviceIndex=0,
        AssociatePublicIpAddress=cfg.getbool("FUZZBUCKET_DEFAULT_PUBLIC_IP"),
        DeleteOnTermination=True,
    )

    subnet_id = aws.find_subnet()

    if subnet_id is not None:
        log.debug(
            f"setting subnet_id={subnet_id!r} on network interface "
            + f"for user={username!r}"
        )

        network_interface["SubnetId"] = subnet_id

    security_groups = cfg.getlist("FUZZBUCKET_DEFAULT_SECURITY_GROUPS")

    if flask.request.json.get("connect") is not None:
        security_groups += cfg.getlist(
            f"fuzzbucket-{cfg.get('FUZZBUCKET_STAGE')}-connect-sg"
        )

    security_groups = aws.resolve_security_groups(security_groups)

    if len(security_groups) > 0:
        network_interface["Groups"] = security_groups

    ami_desc = aws.get_ec2_client().describe_images(ImageIds=[ami])
    if len(ami_desc.get("Images", [])) == 0:
        return (
            flask.jsonify(
                error=f"ami={ami!r} not found or not available to this account"
            ),
            400,
        )

    root_block_device_mapping: dict[str, typing.Any] = dict(
        DeviceName=ami_desc["Images"][0]["RootDeviceName"],
        Ebs=dict(
            DeleteOnTermination=True,
            VolumeSize=[
                bdm["Ebs"]["VolumeSize"]
                for bdm in ami_desc["Images"][0]["BlockDeviceMappings"]
                if bdm["DeviceName"] == ami_desc["Images"][0]["RootDeviceName"]
            ][0],
        ),
    )

    root_volume_size = flask.request.json.get("root_volume_size")

    if root_volume_size is not None:
        root_block_device_mapping["Ebs"]["VolumeSize"] = root_volume_size

    instance_tags: list[dict[str, str]] = [
        dict(Key="Name", Value=name),
        dict(
            Key=tags.Tags.created_at.value, Value=str(datetime_ext.utcnow().timestamp())
        ),
        dict(Key=tags.Tags.image_alias.value, Value=image_alias),
        dict(Key=tags.Tags.ttl.value, Value=ttl),
        dict(Key=tags.Tags.user.value, Value=username),
    ] + [tag_spec.copy() for tag_spec in cfg.DEFAULT_INSTANCE_TAGS]

    for key, value in flask.request.json.get("instance_tags", {}).items():
        tag_spec = dict(Key=str(key), Value=str(value))

        log.debug(f"adding tags from request json 'instance_tags' spec={tag_spec!r}")

        instance_tags.append(tag_spec)

    response = aws.get_ec2_client().run_instances(
        BlockDeviceMappings=[root_block_device_mapping],
        ImageId=ami,
        InstanceType=flask.request.json.get(
            "instance_type",
            cfg.get("FUZZBUCKET_DEFAULT_INSTANCE_TYPE", default="t3.small"),
        ),
        KeyName=resolved_key_name,
        MinCount=1,
        MaxCount=1,
        NetworkInterfaces=[network_interface],
        TagSpecifications=[
            dict(
                ResourceType="instance",
                Tags=instance_tags,
            )
        ],
    )

    return (
        flask.jsonify(
            boxes=[
                box.Box.from_ec2_dict(inst) for inst in response.get("Instances", [])
            ],
            you=username,
        ),
        201,
    )


@bp.route("/<string:instance_id>", methods=("PUT",))
def update_box(instance_id):
    if not auth.is_fully_authd():
        return auth.auth_403()

    log.debug(
        f"handling update_box for user={flask.request.remote_user!r} "
        + f"instance_id={instance_id!r}"
    )

    if instance_id not in [
        b.instance_id
        for b in aws.list_user_boxes(
            aws.get_ec2_client(),
            flask.request.remote_user,
            aws.get_vpc_id(aws.get_ec2_client()),
        )
    ]:
        return flask.jsonify(error="no touching"), 403

    if not flask.request.is_json:
        return flask.jsonify(error="request is not json"), 400

    assert flask.request.json is not None

    instance_tags = []
    for key, value in flask.request.json.get("instance_tags", {}).items():
        tag_spec = dict(Key=str(key), Value=str(value))

        log.debug(f"adding tags from request json 'instance_tags' spec={tag_spec!r}")

        instance_tags.append(tag_spec)

    ttl = (flask.request.json.get("ttl") or "").strip()
    if ttl != "":
        instance_tags.append(dict(Key=tags.Tags.ttl.value, Value=ttl))

    response = aws.get_ec2_client().create_tags(
        Resources=[instance_id], Tags=instance_tags
    )

    return (
        flask.jsonify(
            raw_response=response.get("ResponseMetadata", {}),
            you=flask.request.remote_user,
        ),
        200,
    )


@bp.route("/<string:instance_id>/reboot", methods=("POST",))
def reboot_box(instance_id):
    if not auth.is_fully_authd():
        return auth.auth_403()

    log.debug(
        f"handling reboot_box for user={flask.request.remote_user!r} "
        + f"instance_id={instance_id!r}"
    )

    if instance_id not in [
        b.instance_id
        for b in aws.list_user_boxes(
            aws.get_ec2_client(),
            flask.request.remote_user,
            aws.get_vpc_id(aws.get_ec2_client()),
        )
    ]:
        return flask.jsonify(error="no touching"), 403

    aws.get_ec2_client().reboot_instances(InstanceIds=[instance_id])

    return "", 204


@bp.route("/<string:instance_id>", methods=("DELETE",))
def delete_box(instance_id):
    if not auth.is_fully_authd():
        return auth.auth_403()

    log.debug(
        f"handling delete_box for user={flask.request.remote_user!r} "
        + f"instance_id={instance_id!r}"
    )

    if instance_id not in [
        b.instance_id
        for b in aws.list_user_boxes(
            aws.get_ec2_client(),
            flask.request.remote_user,
            aws.get_vpc_id(aws.get_ec2_client()),
        )
    ]:
        return flask.jsonify(error="no touching"), 403

    aws.get_ec2_client().terminate_instances(InstanceIds=[instance_id])

    return "", 204
