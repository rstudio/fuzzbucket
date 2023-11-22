import functools
import json
import random
import secrets
import typing
import urllib.parse
import warnings

import flask_dance
from botocore.exceptions import ClientError
from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from oauthlib.oauth2.rfc6749.errors import OAuth2Error
from werkzeug.exceptions import InternalServerError

import fuzzbucket.cfg as cfg

from . import (
    AsJSONProvider,
    get_dynamodb,
    get_ec2_client,
    get_vpc_id,
    list_user_boxes,
    utcnow,
)
from .__version__ import __version__
from .box import Box
from .datetime_ext import parse_timedelta
from .flask_dance_storage import FlaskDanceStorage
from .log import log
from .tags import Tags

DEFAULT_HEADERS: tuple[tuple[str, str], ...] = (
    ("server", f"fuzzbucket/{__version__}"),
    ("fuzzbucket-region", str(cfg.get("FUZZBUCKET_REGION"))),
    ("fuzzbucket-version", __version__),
)
DEFAULT_INSTANCE_TAGS: tuple[dict[str, str], ...] = tuple(
    [
        dict(
            Key=urllib.parse.unquote(k.strip()),
            Value=urllib.parse.unquote(v.strip()),
        )
        for k, v in [
            pair.split(":", maxsplit=1)
            for pair in (cfg.get("FUZZBUCKET_DEFAULT_INSTANCE_TAGS") or "").split(",")
            if ":" in pair
        ]
    ]
)
ALLOWED_GITHUB_ORGS: tuple[str, ...] = ()
AUTH_PROVIDER: str = typing.cast(
    str, cfg.get("FUZZBUCKET_AUTH_PROVIDER", default="github-oauth")
)
BRANDING: str = typing.cast(str, cfg.get("FUZZBUCKET_BRANDING"))
OAUTH_MAX_AGE: float = 86400.0
UNKNOWN_AUTH_PROVIDER: ValueError = ValueError(
    f"unknown auth provider {AUTH_PROVIDER!r}"
)

app = Flask(__name__)
app.secret_key = cfg.get("FUZZBUCKET_FLASK_SECRET_KEY")
app.json = AsJSONProvider(app)

session_storage = FlaskDanceStorage(
    table_name=f"fuzzbucket-{cfg.get('FUZZBUCKET_STAGE')}-users"
)
app.config["session_storage"] = session_storage

github: typing.Any = None
oauth_blueprint: typing.Optional["flask_dance.consumer.OAuth2ConsumerBlueprint"] = None

if AUTH_PROVIDER == "github-oauth":
    from flask_dance.contrib.github import github, make_github_blueprint  # type: ignore

    app.config["GITHUB_OAUTH_CLIENT_ID"] = cfg.get("FUZZBUCKET_GITHUB_OAUTH_CLIENT_ID")
    app.config["GITHUB_OAUTH_CLIENT_SECRET"] = cfg.get(
        "FUZZBUCKET_GITHUB_OAUTH_CLIENT_SECRET"
    )
    gh_blueprint = make_github_blueprint(
        scope=["read:org", "read:public_key"],
        redirect_to="github_auth_complete",
        storage=session_storage,
    )
    app.config["gh_blueprint"] = gh_blueprint
    app.register_blueprint(gh_blueprint, url_prefix="/login")

    ALLOWED_GITHUB_ORGS = tuple(cfg.getlist("FUZZBUCKET_ALLOWED_GITHUB_ORGS"))

elif AUTH_PROVIDER == "oauth":
    from flask_dance.consumer import OAuth2ConsumerBlueprint

    OAUTH_MAX_AGE = parse_timedelta(
        typing.cast(
            str,
            cfg.get("FUZZBUCKET_OAUTH_MAX_AGE", default="1 day"),
        )
    ).total_seconds()

    oauth_blueprint = OAuth2ConsumerBlueprint(
        "oauth",
        __name__,
        base_url=cfg.get("FUZZBUCKET_OAUTH_BASE_URL"),
        client_id=cfg.get("FUZZBUCKET_OAUTH_CLIENT_ID"),
        client_secret=cfg.get("FUZZBUCKET_OAUTH_CLIENT_SECRET"),
        authorization_url=cfg.get("FUZZBUCKET_OAUTH_AUTH_URL"),
        authorization_url_params={"max_age": int(OAUTH_MAX_AGE)},
        auto_refresh_url=cfg.get("FUZZBUCKET_OAUTH_TOKEN_URL"),
        token_url=cfg.get("FUZZBUCKET_OAUTH_TOKEN_URL"),
        redirect_to="oauth_complete",
        scope=list(cfg.getlist("FUZZBUCKET_OAUTH_SCOPE")),
        storage=session_storage,
    )
    app.config["oauth_blueprint"] = oauth_blueprint
    app.register_blueprint(oauth_blueprint, url_prefix="/login")

else:
    warnings.warn(f"unknown auth provider {AUTH_PROVIDER!r}")


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
            branding=BRANDING,
            error=f"NOPE={exc}",
        ),
        500,
    )


def nullify_auth():
    log.debug(f"nullifying auth for user={session.get('user')!r}")

    if AUTH_PROVIDER == "github-oauth":
        assert github is not None
        github.token = None

    elif AUTH_PROVIDER == "oauth":
        assert oauth_blueprint is not None
        oauth_blueprint.token = None

    else:
        raise UNKNOWN_AUTH_PROVIDER

    del session["user"]


@app.before_request
def set_user():
    source = "session"

    if session.get("user") is None:
        user, source = request.headers.get("Fuzzbucket-User"), "header"
        if user is None:
            user, source = request.args.get("user"), "qs"

        session["user"] = user

    if session.get("user") is not None:
        lower_user = str(session["user"]).lower()

        if session["user"] != lower_user:
            session["user"] = lower_user
            log.debug(
                f"migrated session user to lowercase session user={session['user']!r}"
            )

    log.debug(f"setting remote_user from user={session['user']!r} source={source!r}")
    request.environ["REMOTE_USER"] = session["user"]

    if AUTH_PROVIDER == "github-oauth":
        assert github is not None

        if not github.authorized:
            log.debug("not currently github authorized; assuming login flow")

            return

        user_response = github.get("/user").json()
        github_login = user_response.get("login")

        if github_login is None:
            log.warning(f"no login available in github user response={user_response!r}")

            nullify_auth()

            return

        if str(github_login).lower() == str(session["user"]).lower():
            log.debug(
                f"github login={github_login!r} case-insensitive matches session"
                f" user={session['user']!r}"
            )
            return

        log.warning(
            f"mismatched github_login={github_login!r} user={session['user']!r}"
        )
        nullify_auth()

    elif AUTH_PROVIDER == "oauth":
        assert oauth_blueprint is not None

        if not oauth_blueprint.authorized or not oauth_blueprint.session.authorized:
            log.debug("not currently authorized; assuming login flow")

            return

        assert oauth_blueprint.session is not None

        userinfo_response = _fetch_oauth_userinfo(oauth_blueprint.session)
        if userinfo_response is None:
            nullify_auth()

            return

        log.debug(f"fetched userinfo={userinfo_response!r}")

        user_email = userinfo_response.get("email")
        if user_email is None:
            log.warning(
                f"no login available in oauth userinfo response={userinfo_response!r}"
            )

            nullify_auth()
            return

        if str(user_email).lower() == str(session["user"]).lower():
            log.debug(
                f"oauth login={user_email!r} case-insensitive matches session "
                + f"user={session['user']!r}"
            )
            return

        log.warning(
            f"mismatched user_email={user_email!r} user={session['user']!r}; "
            + "wiping session user and token"
        )

        nullify_auth()

    else:
        raise UNKNOWN_AUTH_PROVIDER


@app.after_request
def set_default_headers(resp: Response) -> Response:
    for key, value in DEFAULT_HEADERS:
        resp.headers[key] = value

    return resp


def is_fully_authd():
    if AUTH_PROVIDER == "github-oauth":
        assert github is not None

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

    elif AUTH_PROVIDER == "oauth":
        assert oauth_blueprint is not None

        if not oauth_blueprint.authorized or not oauth_blueprint.session.authorized:
            log.debug(f"oauth context not authorized for user={session['user']!r}")

            return False

    else:
        raise UNKNOWN_AUTH_PROVIDER

    header_secret = request.headers.get("Fuzzbucket-Secret")
    storage_secret = app.config["session_storage"].secret

    if header_secret != storage_secret:
        log.debug(
            f"header secret={header_secret!r} does not match stored "
            f"secret={storage_secret!r}"
        )

        return False

    return True


def auth_403():
    if AUTH_PROVIDER == "github-oauth":
        login_url = url_for("github.login", _external=True)
        return (
            jsonify(
                error=f"you must authorize first via {login_url!r}",
                login_url=login_url,
            ),
            403,
        )

    elif AUTH_PROVIDER == "oauth":
        login_url = url_for("oauth.login", _external=True)
        return (
            jsonify(
                error=f"you must authorize first via {login_url!r}",
                login_url=login_url,
            ),
            403,
        )

    else:
        raise UNKNOWN_AUTH_PROVIDER


@app.route("/_login", methods=["GET"])
def login():
    if AUTH_PROVIDER == "github-oauth":
        return redirect(url_for("github.login"))
    elif AUTH_PROVIDER == "oauth":
        return redirect(url_for("oauth.login"))
    else:
        raise UNKNOWN_AUTH_PROVIDER


@app.route("/auth-complete", methods=["GET"])
def github_auth_complete():
    assert github is not None

    log.debug(f"allowed_orgs={ALLOWED_GITHUB_ORGS!r}")

    raw_user_orgs = github.get("/user/orgs").json()
    log.debug(f"raw_user_orgs={raw_user_orgs!r}")

    if "message" in raw_user_orgs:
        return (
            render_template(
                "error.html",
                branding=BRANDING,
                error=f"GitHub API error: {raw_user_orgs['message']}",
            ),
            503,
        )

    user_orgs = {o["login"] for o in raw_user_orgs}

    if len(set(ALLOWED_GITHUB_ORGS) & user_orgs) == 0:
        nullify_auth()

        return (
            render_template(
                "error.html",
                branding=BRANDING,
                error="You are not a member of an allowed GitHub organization.",
            ),
            403,
        )

    return _set_secret_auth_complete()


@app.route("/oauth-complete", methods=["GET"])
def oauth_complete():
    assert oauth_blueprint is not None
    assert oauth_blueprint.session is not None

    return _set_secret_auth_complete()


def _set_secret_auth_complete():
    try:
        secret = secrets.token_urlsafe(31)
        app.config["session_storage"].secret = secret

        return (
            render_template(
                "auth_complete.html",
                branding=BRANDING,
                secret=secret,
            ),
            200,
        )
    except ValueError:
        log.exception(f"failed to set secret for user={session.get('user')!r}")

        return (
            render_template(
                "error.html",
                branding=BRANDING,
                error=f"Failed to set secret for user={session.get('user')!r}",
            ),
            500,
        )


@app.route("/_logout", methods=["POST"])
def logout():
    if not is_fully_authd():
        return jsonify(error="not logged in"), 400

    log.debug(f"handling _logout for user={request.remote_user!r}")

    table = get_dynamodb().Table(f"fuzzbucket-{cfg.get('FUZZBUCKET_STAGE')}-users")
    existing_user = table.get_item(Key=dict(user=request.remote_user))

    if existing_user.get("Item") in (None, {}):
        return jsonify(error=f"no user {existing_user!r}"), 404

    resp = table.delete_item(Key=dict(user=request.remote_user))
    log.debug(f"raw dynamodb response={resp!r}")

    nullify_auth()

    return "", 204


@app.route("/", methods=["GET"])
def list_boxes():
    if not is_fully_authd():
        return auth_403()

    log.debug(f"handling list_boxes for user={request.remote_user!r}")

    return (
        jsonify(
            boxes=list_user_boxes(
                get_ec2_client(),
                request.remote_user,
                get_vpc_id(get_ec2_client()),
            ),
            you=request.remote_user,
        ),
        200,
    )


@app.route("/box", methods=["POST"])
def create_box():
    if not is_fully_authd():
        return auth_403()

    log.debug(f"handling create_box for user={session['user']!r}")

    if not request.is_json:
        return jsonify(error="request is not json"), 400

    assert request.json is not None

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

    if matching_key is None and AUTH_PROVIDER == "github-oauth":
        if full_key_alias != session["user"]:
            return (
                jsonify(
                    error=f"key with alias {key_alias} does not exist",
                    you=request.remote_user,
                ),
                400,
            )

        key_material = _fetch_first_compatible_github_key(session["user"])
        username = session["user"]

        if key_material == "":
            return (
                jsonify(
                    error=f"could not fetch compatible public key for user={username!r}"
                ),
                400,
            )

        get_ec2_client().import_key_pair(
            KeyName=username, PublicKeyMaterial=key_material.encode("utf-8")
        )
        resolved_key_name = username
        log.debug(f"imported compatible public key for user={username!r}")

    name = request.json.get("name")
    if str(name or "").strip() == "":
        name = f"fuzzbucket-{username}-{image_alias}"

    ttl = request.json.get("ttl")
    if str(ttl or "").strip() == "":
        ttl = str(3600 * 4)

    # NOTE: the `ttl` value must by a string for use as a tag
    # value, and it's also nice of us to normalize it to an
    # integer.
    ttl = str(int(ttl))

    for instance in list_user_boxes(
        get_ec2_client(), username, get_vpc_id(get_ec2_client())
    ):
        if instance.name == name:
            return jsonify(boxes=[instance], you=username), 409

    network_interface: dict[str, int | bool | str | list[str]] = dict(
        DeviceIndex=0,
        AssociatePublicIpAddress=cfg.getbool("FUZZBUCKET_DEFAULT_PUBLIC_IP"),
        DeleteOnTermination=True,
    )

    subnet_id = _find_subnet()

    if subnet_id is not None:
        log.debug(
            f"setting subnet_id={subnet_id!r} on network interface "
            + f"for user={username!r}"
        )

        network_interface["SubnetId"] = subnet_id

    security_groups = cfg.getlist("FUZZBUCKET_DEFAULT_SECURITY_GROUPS")

    if request.json.get("connect") is not None:
        security_groups += cfg.getlist(
            f"fuzzbucket-{cfg.get('FUZZBUCKET_STAGE')}-connect-sg"
        )

    security_groups = _resolve_security_groups(security_groups)

    if len(security_groups) > 0:
        network_interface["Groups"] = security_groups

    ami_desc = get_ec2_client().describe_images(ImageIds=[ami])
    if len(ami_desc.get("Images", [])) == 0:
        return (
            jsonify(error=f"ami={ami!r} not found or not available to this account"),
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

    root_volume_size = request.json.get("root_volume_size")

    if root_volume_size is not None:
        root_block_device_mapping["Ebs"]["VolumeSize"] = root_volume_size

    instance_tags: list[dict[str, str]] = [
        dict(Key="Name", Value=name),
        dict(Key=Tags.created_at.value, Value=str(utcnow().timestamp())),
        dict(Key=Tags.image_alias.value, Value=image_alias),
        dict(Key=Tags.ttl.value, Value=ttl),
        dict(Key=Tags.user.value, Value=username),
    ] + [tag_spec.copy() for tag_spec in DEFAULT_INSTANCE_TAGS]

    for key, value in request.json.get("instance_tags", {}).items():
        tag_spec = dict(Key=str(key), Value=str(value))

        log.debug(f"adding tags from request json 'instance_tags' spec={tag_spec!r}")

        instance_tags.append(tag_spec)

    response = get_ec2_client().run_instances(
        BlockDeviceMappings=[root_block_device_mapping],
        ImageId=ami,
        InstanceType=request.json.get(
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
        jsonify(
            boxes=[Box.from_ec2_dict(inst) for inst in response.get("Instances", [])],
            you=username,
        ),
        201,
    )


@app.route("/box/<string:instance_id>", methods=["PUT"])
def update_box(instance_id):
    if not is_fully_authd():
        return auth_403()

    log.debug(
        f"handling update_box for user={request.remote_user!r} "
        + f"instance_id={instance_id!r}"
    )

    if instance_id not in [
        b.instance_id
        for b in list_user_boxes(
            get_ec2_client(), request.remote_user, get_vpc_id(get_ec2_client())
        )
    ]:
        return jsonify(error="no touching"), 403

    if not request.is_json:
        return jsonify(error="request is not json"), 400

    assert request.json is not None

    instance_tags = []
    for key, value in request.json.get("instance_tags", {}).items():
        tag_spec = dict(Key=str(key), Value=str(value))

        log.debug(f"adding tags from request json 'instance_tags' spec={tag_spec!r}")

        instance_tags.append(tag_spec)

    ttl = (request.json.get("ttl") or "").strip()
    if ttl != "":
        instance_tags.append(dict(Key=Tags.ttl.value, Value=ttl))

    response = get_ec2_client().create_tags(Resources=[instance_id], Tags=instance_tags)

    return (
        jsonify(
            raw_response=response.get("ResponseMetadata", {}),
            you=request.remote_user,
        ),
        200,
    )


@app.route("/reboot/<string:instance_id>", methods=["POST"])
def reboot_box(instance_id):
    if not is_fully_authd():
        return auth_403()

    log.debug(
        f"handling reboot_box for user={request.remote_user!r} "
        + f"instance_id={instance_id!r}"
    )

    if instance_id not in [
        b.instance_id
        for b in list_user_boxes(
            get_ec2_client(), request.remote_user, get_vpc_id(get_ec2_client())
        )
    ]:
        return jsonify(error="no touching"), 403

    get_ec2_client().reboot_instances(InstanceIds=[instance_id])

    return "", 204


@app.route("/box/<string:instance_id>", methods=["DELETE"])
def delete_box(instance_id):
    if not is_fully_authd():
        return auth_403()

    log.debug(
        f"handling delete_box for user={request.remote_user!r} "
        + f"instance_id={instance_id!r}"
    )

    if instance_id not in [
        b.instance_id
        for b in list_user_boxes(
            get_ec2_client(), request.remote_user, get_vpc_id(get_ec2_client())
        )
    ]:
        return jsonify(error="no touching"), 403

    get_ec2_client().terminate_instances(InstanceIds=[instance_id])

    return "", 204


@app.route("/image-alias", methods=["GET"])
def list_image_aliases():
    if not is_fully_authd():
        return auth_403()

    log.debug(f"handling list_image_aliases for user={request.remote_user!r}")

    table = get_dynamodb().Table(
        f"fuzzbucket-{cfg.get('FUZZBUCKET_STAGE')}-image-aliases"
    )

    image_aliases = {}
    for item in table.scan().get("Items", []):
        image_aliases[item["alias"]] = item["ami"]

    return jsonify(image_aliases=image_aliases, you=request.remote_user), 200


@app.route("/image-alias", methods=["POST"])
def create_image_alias():
    if not is_fully_authd():
        return auth_403()

    log.debug(f"handling create_image_alias for user={request.remote_user!r}")

    if not request.is_json:
        return jsonify(error="request is not json"), 400

    assert request.json is not None

    table = get_dynamodb().Table(
        f"fuzzbucket-{cfg.get('FUZZBUCKET_STAGE')}-image-aliases"
    )
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
        return auth_403()

    log.debug(
        f"handling delete_image_alias for user={request.remote_user!r} alias={alias!r}"
    )

    table = get_dynamodb().Table(
        f"fuzzbucket-{cfg.get('FUZZBUCKET_STAGE')}-image-aliases"
    )

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
        return auth_403()

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
        return auth_403()

    matching_keys = _find_matching_ec2_key_pairs(session["user"])

    def key_alias(key_name):
        if str(key_name).lower() == str(session["user"]).lower():
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
        return auth_403()

    if not request.is_json:
        return jsonify(error="request must be json", you=request.remote_user), 400

    assert request.json is not None

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

    if not _is_ec2_compatible_key(key_material):
        return (
            jsonify(
                error="key material must be an ec2-compatible format",
                you=request.remote_user,
            ),
            400,
        )

    get_ec2_client().import_key_pair(
        KeyName=full_key_alias, PublicKeyMaterial=key_material.encode("utf-8")
    )
    log.debug(f"imported compatible public key with alias={full_key_alias}")

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
        return auth_403()

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


def _find_subnet() -> str | None:
    default_subnets = cfg.getlist("FUZZBUCKET_DEFAULT_SUBNETS")

    if not cfg.getbool("FUZZBUCKET_AUTO_SUBNET"):
        return (
            _resolve_subnet(random.choice(default_subnets)) if default_subnets else None
        )

    candidate_subnets = (
        get_ec2_client()
        .describe_subnets(
            Filters=[
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
            _resolve_subnet(random.choice(default_subnets)) if default_subnets else None
        )

    candidate_subnets.sort(key=lambda s: s["AvailableIpAddressCount"])

    return candidate_subnets[-1]["SubnetId"]


def _find_matching_ec2_key_pair(user: str) -> typing.Optional[dict]:
    low_user = str(user).lower()

    for key_pair in get_ec2_client().describe_key_pairs().get("KeyPairs", []):
        if key_pair["KeyName"].lower() == low_user:
            return key_pair

    return None


def _find_matching_ec2_key_pairs(prefix: str) -> typing.List[dict]:
    low_prefix = str(prefix).lower()
    ret = []

    for key_pair in get_ec2_client().describe_key_pairs().get("KeyPairs", []):
        key_name = key_pair["KeyName"].lower()
        if key_name == low_prefix or key_name.startswith(low_prefix + "-"):
            ret.append(key_pair)

    return ret


def _resolve_ami_alias(image_alias: str) -> str | None:
    try:
        resp = (
            get_dynamodb()
            .Table(f"fuzzbucket-{cfg.get('FUZZBUCKET_STAGE')}-image-aliases")
            .get_item(Key=dict(alias=image_alias))
        )

        return resp.get("Item", {}).get("ami")
    except ClientError:
        log.exception("oh no boto3")

        return None


def _resolve_security_groups(security_groups: list[str]) -> list[str]:
    log.debug(f"resolving security groups={security_groups!r}")

    return [
        sg
        for sg in [_resolve_security_group(sg_alias) for sg_alias in security_groups]
        if sg != ""
    ]


@functools.cache
def _resolve_security_group(security_group: str) -> str:
    log.debug(f"resolving security group={security_group!r}")

    if security_group.startswith("sg-"):
        return security_group

    candidate_groups = (
        get_ec2_client()
        .describe_security_groups(
            Filters=[
                dict(Name="group-name", Values=[security_group]),
            ],
        )
        .get("SecurityGroups")
    )

    if not candidate_groups:
        return security_group

    return candidate_groups[0].get("GroupId", "")


@functools.cache
def _resolve_subnet(subnet_id_or_name: str) -> str | None:
    log.debug(f"resolving subnet id={subnet_id_or_name!r}")

    return (
        get_ec2_client()
        .describe_security_groups(
            Filters=[
                dict(Name="tag:Name", Values=[subnet_id_or_name]),
            ],
        )
        .get("Subnets", [{"SubnetId": subnet_id_or_name}])[0]
        .get("SubnetId")
    )


def _fetch_first_compatible_github_key(user: str) -> str:
    assert github is not None

    try:
        for key in github.get("/user/keys").json():
            stripped_key = key.get("key", "").strip()
            if _is_ec2_compatible_key(stripped_key):
                return stripped_key

        log.warning(f"no compatible ssh key could be found in github for user={user!r}")

        return ""
    except Exception as exc:
        log.warning(
            f"error while fetching first compatible github key for user={user!r} err={exc}"
        )

        return ""


def _is_ec2_compatible_key(key_material: str) -> bool:
    return key_material.startswith("ssh-rsa") or key_material.startswith("ssh-ed25519")


def _fetch_oauth_userinfo(
    oauth_session: flask_dance.consumer.OAuth2Session,
) -> dict[str, typing.Any] | None:
    assert oauth_session is not None
    assert oauth_session.token is not None

    try:
        return oauth_session.get("userinfo").json()
    except OAuth2Error:
        log.exception(f"failed to get oauth userinfo for user={session['user']!r}")

        return None
