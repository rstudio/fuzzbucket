import base64
import os
import time
import typing
import urllib.request

import boto3

from botocore.exceptions import ClientError

from flask import Flask, jsonify, request, g
from flask.json import JSONEncoder

from werkzeug.exceptions import Forbidden as WerkzeugForbidden

from .box import Box
from .tags import Tags
from . import list_user_boxes, log, NoneString

app = Flask(__name__)


class _JSONEncoder(JSONEncoder):
    def default(self, o: typing.Any) -> typing.Any:
        if hasattr(o, "as_json") and callable(o.as_json):
            return o.as_json()
        if hasattr(o, "__dict__"):
            return o.__dict__
        return JSONEncoder.default(self, o)


app.json_encoder = _JSONEncoder


class _UserMiddleware:
    def __init__(self, app):
        self._app = app

    def __call__(
        self, environ: typing.Dict[str, str], start_response: typing.Callable,
    ) -> typing.Iterable[bytes]:
        user = self._extract_user(environ)
        if user is None:
            return WerkzeugForbidden()(environ, start_response)
        environ["REMOTE_USER"] = user
        return self._app(environ, start_response)

    def _extract_user(self, environ: typing.Dict[str, str]) -> NoneString:
        auth_header = environ.get("HTTP_AUTHORIZATION")
        if auth_header is not None:
            b64_token = auth_header.split(" ")[-1]
            user = base64.b64decode(b64_token).decode("utf-8").split(":")[0]
            return user.split("--")[0]

        if os.getenv("IS_OFFLINE") is not None:
            return "offline"
        return None


app.wsgi_app = _UserMiddleware(app.wsgi_app)  # type: ignore


def get_ec2_client():
    if "ec2_client" not in g:
        g.ec2_client = boto3.client("ec2")
    return g.ec2_client


def get_dynamodb():
    if "dynamodb" not in g:
        if os.getenv("IS_OFFLINE") is not None:
            g.dynamodb = boto3.resource(
                "dynamodb",
                region_name="localhost",
                endpoint_url="http://localhost:8000",
            )
        else:
            g.dynamodb = boto3.resource("dynamodb")
    return g.dynamodb


@app.before_first_request
def _app_setup():
    os.environ.setdefault("CF_VPC", "NOTSET")


@app.route("/", methods=["GET"])
def list_boxes():
    return (
        jsonify(
            boxes=list_user_boxes(
                get_ec2_client(), request.remote_user, os.getenv("CF_VPC")
            )
        ),
        200,
    )


@app.route("/box", methods=["POST"])
def create_box():
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

    existing_keys = get_ec2_client().describe_key_pairs(
        Filters=[dict(Name="key-name", Values=[request.remote_user])]
    )
    if len(existing_keys["KeyPairs"]) == 0:
        key_material = _fetch_first_github_key(request.remote_user)
        if key_material.strip() == "":
            return (
                jsonify(
                    error=f"could not fetch public key for user={request.remote_user}"
                ),
                400,
            )

        get_ec2_client().import_key_pair(
            KeyName=request.remote_user, PublicKeyMaterial=key_material.encode("utf-8")
        )
        log.debug(f"imported public key for user={request.remote_user}")

    name = request.json.get("name")
    if str(name or "").strip() == "":
        name = f"fuzzbucket-{request.remote_user}-{image_alias}"

    ttl = request.json.get("ttl")
    if str(ttl or "").strip() == "":
        ttl = str(3600 * 4)

    for instance in list_user_boxes(
        get_ec2_client(), request.remote_user, os.getenv("CF_VPC")
    ):
        if instance.name == name:
            return jsonify(boxes=[instance]), 409

    network_interface = dict(
        DeviceIndex=0, AssociatePublicIpAddress=True, DeleteOnTermination=True,
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

    response = get_ec2_client().run_instances(
        ImageId=ami,
        InstanceType=request.json.get(
            "instance_type", os.getenv("FUZZBUCKET_DEFAULT_INSTANCE_TYPE", "t3.small"),
        ),
        KeyName=request.remote_user,
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
                    dict(Key=Tags.user.value, Value=request.remote_user),
                ],
            )
        ],
    )
    return (
        jsonify(
            boxes=[Box.from_ec2_dict(inst) for inst in response.get("Instances", [])]
        ),
        201,
    )


@app.route("/reboot/<string:instance_id>", methods=["POST"])
def reboot_box(instance_id):
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
    table = get_dynamodb().Table(os.getenv("FUZZBUCKET_IMAGE_ALIASES_TABLE_NAME"))
    image_aliases = {}
    for item in table.scan().get("Items", []):
        image_aliases[item["alias"]] = item["ami"]
    return jsonify(image_aliases=image_aliases), 200


@app.route("/image-alias", methods=["POST"])
def create_image_alias():
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
    return jsonify(image_aliases=[{request.json["alias"]: request.json["ami"]}]), 201


@app.route("/image-alias/<string:alias>", methods=["DELETE"])
def delete_image_alias(alias):
    table = get_dynamodb().Table(os.getenv("FUZZBUCKET_IMAGE_ALIASES_TABLE_NAME"))
    existing_alias = table.get_item(Key=dict(alias=alias))
    if existing_alias.get("Item") in (None, {}):
        return jsonify(error=f"no alias {alias!r}"), 404
    if existing_alias.get("Item").get("user") != request.remote_user:
        return jsonify(error="no touching"), 403
    resp = table.delete_item(Key=dict(alias=alias))
    log.debug(f"raw dynamodb response={resp!r}")
    return "", 204


def _resolve_ami_alias(image_alias: str) -> typing.Union[str, None]:
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


def _fetch_first_github_key(user: str) -> str:
    try:
        with urllib.request.urlopen(f"https://github.com/{user}.keys") as response:
            return response.read().decode("utf-8").split("\n")[0].strip()
    except urllib.request.HTTPError as exc:  # type: ignore
        log.warning(f"error while fetching keys for user={user} err={exc}")
        return ""
