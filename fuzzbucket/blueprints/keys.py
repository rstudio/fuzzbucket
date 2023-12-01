import flask
import flask_login

from .. import aws
from ..log import log

bp = flask.Blueprint("keys", __name__)


@bp.route("/<string:alias>", methods=("GET",))
@flask_login.login_required
def get_key(alias):
    user_id: str = flask_login.current_user.get_id()

    full_key_alias = user_id
    if str(alias).lower() != "default":
        full_key_alias = f"{user_id}-{alias}"

    matching_key = aws.find_matching_ec2_key_pair(full_key_alias)

    if matching_key is None:
        return (
            flask.jsonify(error="no key exists for you", you=user_id),
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
            you=user_id,
        ),
        200,
    )


@bp.route("/", methods=("GET",), strict_slashes=False)
@flask_login.login_required
def list_keys():
    user_id: str = flask_login.current_user.get_id()

    matching_keys = aws.find_matching_ec2_key_pairs(user_id)

    def key_alias(key_name):
        if str(key_name).lower() == str(user_id).lower():
            return "default"

        return key_name.replace(f"{user_id}-", "")

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
            you=user_id,
        ),
        200,
    )


@bp.route("/<string:alias>", methods=("PUT",))
@flask_login.login_required
def put_key(alias):
    user_id: str = flask_login.current_user.get_id()

    if not flask.request.is_json:
        return (
            flask.jsonify(error="request must be json", you=user_id),
            400,
        )

    assert flask.request.json is not None

    full_key_alias = user_id
    if str(alias).lower() != "default":
        full_key_alias = f"{user_id}-{alias}"

    log.debug("checking for existence of key", extra=dict(alias=full_key_alias))

    matching_key = aws.find_matching_ec2_key_pair(full_key_alias)
    if matching_key is not None:
        return (
            flask.jsonify(
                error="key already exists and cannot be updated",
                you=user_id,
            ),
            409,
        )

    key_material = str(flask.request.json.get("key_material", "")).strip()
    if len(key_material) == 0:
        return (
            flask.jsonify(
                error="request is missing key_material",
                you=user_id,
            ),
            400,
        )

    if not aws.is_ec2_compatible_key(key_material):
        return (
            flask.jsonify(
                error="key material must be an ec2-compatible format",
                you=user_id,
            ),
            400,
        )

    aws.get_ec2_client().import_key_pair(
        KeyName=full_key_alias, PublicKeyMaterial=key_material.encode("utf-8")
    )
    log.debug("imported compatible public key", extra=dict(alias=full_key_alias))

    matching_key = aws.find_matching_ec2_key_pair(full_key_alias)
    if matching_key is None:
        return (
            flask.jsonify(
                error="failed to re-fetch key after import",
                you=user_id,
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
            you=user_id,
        ),
        201,
    )


@bp.route("/<string:alias>", methods=("DELETE",))
@flask_login.login_required
def delete_key(alias):
    user_id: str = flask_login.current_user.get_id()

    full_key_alias = user_id
    if str(alias).lower() != "default":
        full_key_alias = f"{user_id}-{alias}"

    matching_key = aws.find_matching_ec2_key_pair(full_key_alias)
    if matching_key is None:
        return (
            flask.jsonify(
                error="no key to delete for you",
                you=user_id,
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
            you=user_id,
        ),
        200,
    )
