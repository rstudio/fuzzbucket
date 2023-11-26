import flask

from .. import auth, aws
from ..log import log

bp = flask.Blueprint("keys", __name__)


@bp.route("/<string:alias>", methods=("GET",))
def get_key(alias):
    if not auth.is_fully_authd():
        return auth.auth_403()

    full_key_alias = flask.session["user"]
    if str(alias).lower() != "default":
        full_key_alias = f"{flask.session['user']}-{alias}"

    matching_key = aws.find_matching_ec2_key_pair(full_key_alias)

    if matching_key is None:
        return (
            flask.jsonify(error="no key exists for you", you=flask.request.remote_user),
            404,
        )

    return (
        flask.jsonify(
            key=dict(
                name=matching_key["KeyName"],
                alias=full_key_alias,
                key_pair_id=matching_key["KeyPairId"],
                ec2_fingerprint=matching_key["KeyFingerprint"],
            ),
            you=flask.request.remote_user,
        ),
        200,
    )


@bp.route("/", methods=("GET",), strict_slashes=False)
def list_keys():
    if not auth.is_fully_authd():
        return auth.auth_403()

    matching_keys = aws.find_matching_ec2_key_pairs(flask.session["user"])

    def key_alias(key_name):
        if str(key_name).lower() == str(flask.session["user"]).lower():
            return "default"

        return key_name.replace(f"{flask.session['user']}-", "")

    return (
        flask.jsonify(
            keys=[
                dict(
                    name=matching_key["KeyName"],
                    alias=key_alias(matching_key["KeyName"]),
                    key_pair_id=matching_key["KeyPairId"],
                    ec2_fingerprint=matching_key["KeyFingerprint"],
                )
                for matching_key in matching_keys
            ],
            you=flask.request.remote_user,
        ),
        200,
    )


@bp.route("/<string:alias>", methods=("PUT",))
def put_key(alias):
    if not auth.is_fully_authd():
        return auth.auth_403()

    if not flask.request.is_json:
        return (
            flask.jsonify(error="request must be json", you=flask.request.remote_user),
            400,
        )

    assert flask.request.json is not None

    full_key_alias = flask.session["user"]
    if str(alias).lower() != "default":
        full_key_alias = f"{flask.session['user']}-{alias}"

    log.debug(f"checking for existence of key with alias={full_key_alias}")

    matching_key = aws.find_matching_ec2_key_pair(full_key_alias)
    if matching_key is not None:
        return (
            flask.jsonify(
                error="key already exists and cannot be updated",
                you=flask.request.remote_user,
            ),
            409,
        )

    key_material = str(flask.request.json.get("key_material", "")).strip()
    if len(key_material) == 0:
        return (
            flask.jsonify(
                error="request is missing key_material", you=flask.request.remote_user
            ),
            400,
        )

    if not aws.is_ec2_compatible_key(key_material):
        return (
            flask.jsonify(
                error="key material must be an ec2-compatible format",
                you=flask.request.remote_user,
            ),
            400,
        )

    aws.get_ec2_client().import_key_pair(
        KeyName=full_key_alias, PublicKeyMaterial=key_material.encode("utf-8")
    )
    log.debug(f"imported compatible public key with alias={full_key_alias}")

    matching_key = aws.find_matching_ec2_key_pair(full_key_alias)
    if matching_key is None:
        return (
            flask.jsonify(
                error="failed to re-fetch key after import",
                you=flask.request.remote_user,
            ),
            500,
        )

    return (
        flask.jsonify(
            key=dict(
                name=matching_key["KeyName"],
                key_pair_id=matching_key["KeyPairId"],
                ec2_fingerprint=matching_key["KeyFingerprint"],
            ),
            you=flask.request.remote_user,
        ),
        201,
    )


@bp.route("/<string:alias>", methods=("DELETE",))
def delete_key(alias):
    if not auth.is_fully_authd():
        return auth.auth_403()

    full_key_alias = flask.session["user"]
    if str(alias).lower() != "default":
        full_key_alias = f"{flask.session['user']}-{alias}"

    matching_key = aws.find_matching_ec2_key_pair(full_key_alias)
    if matching_key is None:
        return (
            flask.jsonify(
                error="no key to delete for you", you=flask.request.remote_user
            ),
            404,
        )

    aws.get_ec2_client().delete_key_pair(KeyName=matching_key["KeyName"])

    return (
        flask.jsonify(
            key=dict(
                name=matching_key["KeyName"],
                key_pair_id=matching_key["KeyPairId"],
                ec2_fingerprint=matching_key["KeyFingerprint"],
            ),
            you=flask.request.remote_user,
        ),
        200,
    )
