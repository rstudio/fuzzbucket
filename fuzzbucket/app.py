import base64
import os
import time
import urllib.request

import boto3

from flask import Flask, jsonify, request, g
from flask.json import JSONEncoder

from werkzeug.exceptions import Forbidden as WerkzeugForbidden

from .image_aliases import image_aliases
from .box import Box
from .tags import Tags
from . import list_user_boxes, log

app = Flask(__name__)


class _JSONEncoder(JSONEncoder):
    def default(self, o):
        if hasattr(o, "as_json") and callable(o.as_json):
            return o.as_json()
        if hasattr(o, "__dict__"):
            return o.__dict__
        return JSONEncoder.default(self, o)


app.json_encoder = _JSONEncoder


class _UserMiddleware:
    def __init__(self, app):
        self._app = app

    def __call__(self, environ, start_response):
        user = self._extract_user(environ)
        if user is None:
            return WerkzeugForbidden()(environ, start_response)
        environ["REMOTE_USER"] = user
        return self._app(environ, start_response)

    def _extract_user(self, environ):
        auth_header = environ.get("HTTP_AUTHORIZATION")
        if auth_header is not None:
            b64_token = auth_header.split(" ")[-1]
            user = base64.b64decode(b64_token).decode("utf-8").split(":")[0]
            return user.split("--")[0]

        if os.getenv("IS_OFFLINE") is not None:
            return "offline"
        return None


app.wsgi_app = _UserMiddleware(app.wsgi_app)


def get_ec2_client():
    if "ec2_client" not in g:
        g.ec2_client = boto3.client("ec2")
    return g.ec2_client


def get_dynamodb_client():
    if "dynamodb_client" not in g:
        if os.getenv("IS_OFFLINE") is not None:
            g.dynamodb_client = boto3.client(
                "dynamodb",
                region_name="localhost",
                endpoint_url="http://localhost:8000",
            )
        else:
            g.dynamodb_client = boto3.client("dynamodb")
    return g.dynamodb_client


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


@app.route("/image-alias", methods=["GET"])
def list_image_aliases():
    return jsonify(image_aliases=image_aliases), 200


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
        200,
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


def _resolve_ami_alias(image_alias):
    return image_aliases.get(image_alias, None)


def _fetch_first_github_key(user):
    try:
        with urllib.request.urlopen(f"https://github.com/{user}.keys") as response:
            return response.read().decode("utf-8").split("\n")[0].strip()
    except urllib.request.HTTPError as exc:
        log.warning(f"error while fetching keys for user={user} err={exc}")
        return ""
