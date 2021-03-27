import json
import os
import time
import typing

from botocore.exceptions import ClientError

from flask import Flask, jsonify, request, url_for, session, redirect, render_template
from flask_dance.contrib.github import make_github_blueprint, github
from werkzeug.exceptions import InternalServerError

from .box import Box
from .tags import Tags
from .flask_dance_storage import FlaskDanceStorage
from . import (
    AsJSONEncoder,
    NoneString,
    get_dynamodb,
    get_ec2_client,
    list_user_boxes,
    log,
)


app = Flask(__name__)
app.secret_key = os.getenv("FUZZBUCKET_FLASK_SECRET_KEY")
app.config["GITHUB_OAUTH_CLIENT_ID"] = os.getenv("FUZZBUCKET_GITHUB_OAUTH_CLIENT_ID")
app.config["GITHUB_OAUTH_CLIENT_SECRET"] = os.getenv(
    "FUZZBUCKET_GITHUB_OAUTH_CLIENT_SECRET"
)
gh_storage = FlaskDanceStorage(table_name=os.getenv("FUZZBUCKET_USERS_TABLE_NAME"))
app.config["gh_storage"] = gh_storage
gh_blueprint = make_github_blueprint(
    scope="read:org,read:public_key",
    redirect_to="auth_complete",
    storage=gh_storage,
)
app.config["gh_blueprint"] = gh_blueprint
app.register_blueprint(gh_blueprint, url_prefix="/login")
app.json_encoder = AsJSONEncoder


@app.errorhandler(InternalServerError)
def handle_500(exc):
    log.debug(f"handling internal server error={exc!r}")
    if getattr(exc, "original_exception", None) is not None:
        exc = exc.original_exception

    if hasattr(exc, "get_response"):
        response = exc.get_response()
        if response is not None and response.is_json:
            return json.dumps(dict(error=str(exc))), 500
    return (
        render_template(
            "error.html",
            branding=os.getenv("FUZZBUCKET_BRANDING"),
            error=f"NOPE={exc}",
        ),
        500,
    )


@app.before_first_request
def _app_setup():
    os.environ.setdefault("CF_VPC", "NOTSET")


@app.before_request
def set_user():
    source = "session"
    if session.get("user") is None:
        user, source = request.headers.get("Fuzzbucket-User"), "header"
        if user is None:
            user, source = request.args.get("user"), "qs"
        session["user"] = user
    log.debug(f"setting remote_user from user={session['user']!r} source={source!r}")
    request.environ["REMOTE_USER"] = session["user"]
    if not github.authorized:
        log.debug("not currently github authorized; assuming login flow")
        return
    github_login = github.get("/user").json()["login"]
    if str(github_login).lower() == str(session["user"]).lower():
        log.debug(
            f"github login={github_login!r} case-insensitive matches session"
            f" user={session['user']!r}"
        )
        return
    log.warning(f"mismatched github_login={github_login!r} user={session['user']!r}")
    github.token = None
    del session["user"]


def is_fully_authd():
    if not github.authorized:
        log.debug(f"github context not authorized for user={session['user']!r}")
        return False

    session_user_lower = str(session["user"]).lower()
    github_login_lower = str(github.get("/user").json()["login"]).lower()

    if session_user_lower != github_login_lower:
        log.debug(
            f"session user={session_user_lower!r} does not match github"
            f" login={github_login_lower}"
        )
        return False

    header_secret = request.headers.get("Fuzzbucket-Secret")
    storage_secret = app.config["gh_storage"].secret()

    if header_secret != storage_secret:
        log.debug(
            f"header secret={header_secret} does not match stored"
            f" secret={storage_secret}"
        )
        return False

    return True


def auth_403_github():
    login_url = url_for("github.login", _external=True)
    return (
        jsonify(
            error=f"you must authorize first via {login_url!r}",
            login_url=login_url,
        ),
        403,
    )


@app.route("/_login", methods=["GET"])
def _login():
    return redirect(url_for("github.login"))


@app.route("/auth-complete", methods=["GET"])
def auth_complete():
    allowed_orgs = {
        s.strip() for s in os.getenv("FUZZBUCKET_ALLOWED_GITHUB_ORGS").split()
    }
    log.debug(f"allowed_orgs={allowed_orgs!r}")
    raw_user_orgs = github.get("/user/orgs").json()
    log.debug(f"raw_user_orgs={raw_user_orgs!r}")
    if "message" in raw_user_orgs:
        return (
            render_template(
                "error.html",
                branding=os.getenv("FUZZBUCKET_BRANDING"),
                error=f"GitHub API error: {raw_user_orgs['message']}",
            ),
            503,
        )

    user_orgs = {o["login"] for o in raw_user_orgs}
    if len(allowed_orgs.intersection(user_orgs)) == 0:
        github.token = None
        del session["user"]
        return (
            render_template(
                "error.html",
                branding=os.getenv("FUZZBUCKET_BRANDING"),
                error="You are not a member of an allowed GitHub organization.",
            ),
            403,
        )
    try:
        secret = app.config["gh_storage"].secret()
        return (
            render_template(
                "auth_complete.html",
                branding=os.getenv("FUZZBUCKET_BRANDING"),
                secret=secret,
            ),
            200,
        )
    except ValueError:
        return (
            render_template(
                "error.html",
                branding=os.getenv("FUZZBUCKET_BRANDING"),
                error="There is no secret available for user={user!r}",
            ),
            404,
        )


@app.route("/_logout", methods=["POST"])
def logout():
    if not is_fully_authd():
        return jsonify(error="not logged in"), 400
    log.debug(f"handling _logout for user={request.remote_user!r}")
    table = get_dynamodb().Table(os.getenv("FUZZBUCKET_USERS_TABLE_NAME"))
    existing_user = table.get_item(Key=dict(user=request.remote_user))
    if existing_user.get("Item") in (None, {}):
        return jsonify(error=f"no user {existing_user!r}"), 404
    resp = table.delete_item(Key=dict(user=request.remote_user))
    log.debug(f"raw dynamodb response={resp!r}")
    del session["user"]
    return "", 204


@app.route("/", methods=["GET"])
def list_boxes():
    if not is_fully_authd():
        return auth_403_github()
    log.debug(f"handling list_boxes for user={request.remote_user!r}")
    return (
        jsonify(
            boxes=list_user_boxes(
                get_ec2_client(), request.remote_user, os.getenv("CF_VPC")
            ),
            you=request.remote_user,
        ),
        200,
    )


@app.route("/box", methods=["POST"])
def create_box():
    if not is_fully_authd():
        return auth_403_github()
    log.debug(f"handling create_box for user={session['user']}")
    if not request.is_json:
        return jsonify(error="request is not json"), 400
    ami = request.json.get("ami")
    if ami is not None:
        image_alias = "custom"
    else:
        image_alias = request.json.get("image_alias", "ubuntu18")
        ami = _resolve_ami_alias(image_alias)
    if ami is None:
        return jsonify(error=f"unknown image_alias={image_alias}"), 400

    key_alias = request.json.get("key_alias", "default")

    full_key_alias = session["user"]
    if str(key_alias).lower() != "default":
        full_key_alias = f"{session['user']}-{key_alias}"

    matching_key = _find_matching_ec2_key_pair(full_key_alias)
    username = session["user"]
    resolved_key_name = (matching_key or {}).get("KeyName")

    if matching_key is None:
        if full_key_alias != session["user"]:
            return (
                jsonify(
                    error=f"key with alias {key_alias} does not exist",
                    you=request.remote_user,
                ),
                400,
            )

        key_material = _fetch_first_github_rsa_key(session["user"])
        username = session["user"]
        if key_material == "":
            return (
                jsonify(error=f"could not fetch rsa public key for user={username}"),
                400,
            )

        get_ec2_client().import_key_pair(
            KeyName=username, PublicKeyMaterial=key_material.encode("utf-8")
        )
        resolved_key_name = username
        log.debug(f"imported rsa public key for user={username}")

    name = request.json.get("name")
    if str(name or "").strip() == "":
        name = f"fuzzbucket-{username}-{image_alias}"

    ttl = request.json.get("ttl")
    if str(ttl or "").strip() == "":
        ttl = str(3600 * 4)

    for instance in list_user_boxes(get_ec2_client(), username, os.getenv("CF_VPC")):
        if instance.name == name:
            return jsonify(boxes=[instance], you=username), 409

    network_interface = dict(
        DeviceIndex=0,
        AssociatePublicIpAddress=True,
        DeleteOnTermination=True,
    )

    subnet_id = os.getenv("CF_PublicSubnet", None)
    if subnet_id is not None:
        network_interface["SubnetId"] = subnet_id
    security_groups = [
        sg.strip()
        for sg in os.getenv("CF_FuzzbucketDefaultSecurityGroup", "").split(" ")
    ]

    if request.json.get("connect") is not None:
        security_groups += [
            sg.strip()
            for sg in os.getenv("CF_FuzzbucketConnectSecurityGroup", "").split(" ")
        ]
    if len(security_groups) > 0:
        network_interface["Groups"] = security_groups

    ami_desc = get_ec2_client().describe_images(ImageIds=[ami])
    if len(ami_desc.get("Images", [])) == 0:
        return (
            jsonify(error=f"ami={ami!r} not found or not available to this account"),
            400,
        )

    root_block_device_mapping = dict(
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

    root_volume_size = request.json.get("root_volume_size")

    if root_volume_size is not None:
        root_block_device_mapping["Ebs"]["VolumeSize"] = root_volume_size

    response = get_ec2_client().run_instances(
        BlockDeviceMappings=[root_block_device_mapping],
        ImageId=ami,
        InstanceType=request.json.get(
            "instance_type",
            os.getenv("FUZZBUCKET_DEFAULT_INSTANCE_TYPE", "t3.small"),
        ),
        KeyName=resolved_key_name,
        MinCount=1,
        MaxCount=1,
        NetworkInterfaces=[network_interface],
        TagSpecifications=[
            dict(
                ResourceType="instance",
                Tags=[
                    dict(Key="Name", Value=name),
                    dict(Key=Tags.created_at.value, Value=str(time.time())),
                    dict(Key=Tags.image_alias.value, Value=image_alias),
                    dict(Key=Tags.ttl.value, Value=ttl),
                    dict(Key=Tags.user.value, Value=username),
                ],
            )
        ],
    )

    return (
        jsonify(
            boxes=[Box.from_ec2_dict(inst) for inst in response.get("Instances", [])],
            you=username,
        ),
        201,
    )


@app.route("/reboot/<string:instance_id>", methods=["POST"])
def reboot_box(instance_id):
    if not is_fully_authd():
        return auth_403_github()
    log.debug(
        f"handling reboot_box for user={request.remote_user!r} "
        + f"instance_id={instance_id!r}"
    )
    if instance_id not in [
        b.instance_id
        for b in list_user_boxes(
            get_ec2_client(), request.remote_user, os.getenv("CF_VPC")
        )
    ]:
        return jsonify(error="no touching"), 403
    get_ec2_client().reboot_instances(InstanceIds=[instance_id])
    return "", 204


@app.route("/box/<string:instance_id>", methods=["DELETE"])
def delete_box(instance_id):
    if not is_fully_authd():
        return auth_403_github()
    log.debug(
        f"handling delete_box for user={request.remote_user!r} "
        + f"instance_id={instance_id!r}"
    )
    if instance_id not in [
        b.instance_id
        for b in list_user_boxes(
            get_ec2_client(), request.remote_user, os.getenv("CF_VPC")
        )
    ]:
        return jsonify(error="no touching"), 403
    get_ec2_client().terminate_instances(InstanceIds=[instance_id])
    return "", 204


@app.route("/image-alias", methods=["GET"])
def list_image_aliases():
    if not is_fully_authd():
        return auth_403_github()
    log.debug(f"handling list_image_aliases for user={request.remote_user!r}")
    table = get_dynamodb().Table(os.getenv("FUZZBUCKET_IMAGE_ALIASES_TABLE_NAME"))
    image_aliases = {}
    for item in table.scan().get("Items", []):
        image_aliases[item["alias"]] = item["ami"]
    return jsonify(image_aliases=image_aliases, you=request.remote_user), 200


@app.route("/image-alias", methods=["POST"])
def create_image_alias():
    if not is_fully_authd():
        return auth_403_github()
    log.debug(f"handling create_image_alias for user={request.remote_user!r}")
    if not request.is_json:
        return jsonify(error="request is not json"), 400
    table = get_dynamodb().Table(os.getenv("FUZZBUCKET_IMAGE_ALIASES_TABLE_NAME"))
    resp = table.put_item(
        Item=dict(
            user=request.remote_user,
            alias=request.json["alias"],
            ami=request.json["ami"],
        ),
    )
    log.debug(f"raw dynamodb response={resp!r}")
    return (
        jsonify(
            image_aliases={request.json["alias"]: request.json["ami"]},
            you=request.remote_user,
        ),
        201,
    )


@app.route("/image-alias/<string:alias>", methods=["DELETE"])
def delete_image_alias(alias):
    if not is_fully_authd():
        return auth_403_github()
    log.debug(
        f"handling delete_image_alias for user={request.remote_user!r} alias={alias!r}"
    )
    table = get_dynamodb().Table(os.getenv("FUZZBUCKET_IMAGE_ALIASES_TABLE_NAME"))
    existing_alias = table.get_item(Key=dict(alias=alias))
    if existing_alias.get("Item") in (None, {}):
        return jsonify(error=f"no alias {alias!r}"), 404
    if existing_alias.get("Item").get("user") != request.remote_user:
        return jsonify(error="no touching"), 403
    resp = table.delete_item(Key=dict(alias=alias))
    log.debug(f"raw dynamodb response={resp!r}")
    return "", 204


@app.route("/key", defaults={"alias": "default"}, methods=["GET"])
@app.route("/key/<string:alias>", methods=["GET"])
def get_key(alias):
    if not is_fully_authd():
        return auth_403_github()

    full_key_alias = session["user"]
    if str(alias).lower() != "default":
        full_key_alias = f"{session['user']}-{alias}"

    matching_key = _find_matching_ec2_key_pair(full_key_alias)

    if matching_key is None:
        return jsonify(error="no key exists for you", you=request.remote_user), 404
    return (
        jsonify(
            key=dict(
                name=matching_key["KeyName"],
                alias=full_key_alias,
                key_pair_id=matching_key["KeyPairId"],
                ec2_fingerprint=matching_key["KeyFingerprint"],
            ),
            you=request.remote_user,
        ),
        200,
    )


@app.route("/keys", methods=["GET"])
def list_keys():
    if not is_fully_authd():
        return auth_403_github()

    matching_keys = _find_matching_ec2_key_pairs(session["user"])

    def key_alias(key_name):
        if key_name == session["user"]:
            return "default"
        return key_name.replace(f"{session['user']}-", "")

    return (
        jsonify(
            keys=[
                dict(
                    name=matching_key["KeyName"],
                    alias=key_alias(matching_key["KeyName"]),
                    key_pair_id=matching_key["KeyPairId"],
                    ec2_fingerprint=matching_key["KeyFingerprint"],
                )
                for matching_key in matching_keys
            ],
            you=request.remote_user,
        ),
        200,
    )


@app.route("/key", defaults={"alias": "default"}, methods=["PUT"])
@app.route("/key/<string:alias>", methods=["PUT"])
def put_key(alias):
    if not is_fully_authd():
        return auth_403_github()

    if not request.is_json:
        return jsonify(error="request must be json", you=request.remote_user), 400

    full_key_alias = session["user"]
    if str(alias).lower() != "default":
        full_key_alias = f"{session['user']}-{alias}"

    log.debug(f"checking for existence of key with alias={full_key_alias}")

    matching_key = _find_matching_ec2_key_pair(full_key_alias)
    if matching_key is not None:
        return (
            jsonify(
                error="key already exists and cannot be updated",
                you=request.remote_user,
            ),
            409,
        )

    key_material = str(request.json.get("key_material", "")).strip()
    if len(key_material) == 0:
        return (
            jsonify(error="request is missing key_material", you=request.remote_user),
            400,
        )

    if not key_material.startswith("ssh-rsa"):
        return (
            jsonify(
                error="key material must be of type ssh-rsa", you=request.remote_user
            ),
            400,
        )

    get_ec2_client().import_key_pair(
        KeyName=full_key_alias, PublicKeyMaterial=key_material.encode("utf-8")
    )
    log.debug(f"imported rsa public key with alias={full_key_alias}")

    matching_key = _find_matching_ec2_key_pair(full_key_alias)
    if matching_key is None:
        return (
            jsonify(
                error="failed to re-fetch key after import", you=request.remote_user
            ),
            500,
        )

    return (
        jsonify(
            key=dict(
                name=matching_key["KeyName"],
                key_pair_id=matching_key["KeyPairId"],
                ec2_fingerprint=matching_key["KeyFingerprint"],
            ),
            you=request.remote_user,
        ),
        201,
    )


@app.route("/key", defaults={"alias": "default"}, methods=["DELETE"])
@app.route("/key/<string:alias>", methods=["DELETE"])
def delete_key(alias):
    if not is_fully_authd():
        return auth_403_github()

    full_key_alias = session["user"]
    if str(alias).lower() != "default":
        full_key_alias = f"{session['user']}-{alias}"

    matching_key = _find_matching_ec2_key_pair(full_key_alias)
    if matching_key is None:
        return jsonify(error="no key to delete for you", you=request.remote_user), 404

    get_ec2_client().delete_key_pair(KeyName=matching_key["KeyName"])
    return (
        jsonify(
            key=dict(
                name=matching_key["KeyName"],
                key_pair_id=matching_key["KeyPairId"],
                ec2_fingerprint=matching_key["KeyFingerprint"],
            ),
            you=request.remote_user,
        ),
        200,
    )


def _find_matching_ec2_key_pair(user: str) -> typing.Optional[dict]:
    low_user = str(user).lower()

    for key_pair in get_ec2_client().describe_key_pairs().get("KeyPairs", []):
        if key_pair["KeyName"].lower() == low_user:
            return key_pair

    return None


def _resolve_ami_alias(image_alias: str) -> NoneString:
    try:
        resp = (
            get_dynamodb()
            .Table(os.getenv("FUZZBUCKET_IMAGE_ALIASES_TABLE_NAME"))
            .get_item(Key=dict(alias=image_alias))
        )
        return resp.get("Item", {}).get("ami")
    except ClientError:
        log.exception("oh no boto3")
        return None


def _fetch_first_github_rsa_key(user: str) -> str:
    try:
        for key in github.get("/user/keys").json():
            stripped_key = key.get("key", "").strip()
            if stripped_key.startswith("ssh-rsa"):
                return stripped_key
        log.warning(f"no ssh-rsa key could be found in github for user={user}")
        return ""
    except Exception as exc:
        log.warning(
            f"error while fetching first github ssh-rsa key for user={user} err={exc}"
        )
        return ""
