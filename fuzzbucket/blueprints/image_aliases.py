import flask

from .. import auth, aws, cfg
from ..log import log

bp = flask.Blueprint("image_aliases", __name__)


@bp.route("/", methods=("GET",), strict_slashes=False)
def list_image_aliases():
    if not auth.is_fully_authd():
        return auth.auth_403()

    log.debug(f"handling list_image_aliases for user={flask.request.remote_user!r}")

    table = aws.get_dynamodb().Table(f"fuzzbucket-{cfg.STAGE}-image-aliases")

    image_aliases = {}
    for item in table.scan().get("Items", []):
        image_aliases[item["alias"]] = item["ami"]

    return (
        flask.jsonify(image_aliases=image_aliases, you=flask.request.remote_user),
        200,
    )


@bp.route("/", methods=("POST",), strict_slashes=False)
def create_image_alias():
    if not auth.is_fully_authd():
        return auth.auth_403()

    log.debug(f"handling create_image_alias for user={flask.request.remote_user!r}")

    if not flask.request.is_json:
        return flask.jsonify(error="request is not json"), 400

    assert flask.request.json is not None

    table = aws.get_dynamodb().Table(
        f"fuzzbucket-{cfg.get('FUZZBUCKET_STAGE')}-image-aliases"
    )
    resp = table.put_item(
        Item=dict(
            user=flask.request.remote_user,
            alias=flask.request.json["alias"],
            ami=flask.request.json["ami"],
        ),
    )

    log.debug(f"raw dynamodb response={resp!r}")

    return (
        flask.jsonify(
            image_aliases={flask.request.json["alias"]: flask.request.json["ami"]},
            you=flask.request.remote_user,
        ),
        201,
    )


@bp.route("/<string:alias>", methods=("DELETE",))
def delete_image_alias(alias):
    if not auth.is_fully_authd():
        return auth.auth_403()

    log.debug(
        f"handling delete_image_alias for user={flask.request.remote_user!r} alias={alias!r}"
    )

    table = aws.get_dynamodb().Table(f"fuzzbucket-{cfg.STAGE}-image-aliases")

    existing_alias = table.get_item(Key=dict(alias=alias))
    if existing_alias.get("Item") in (None, {}):
        return flask.jsonify(error=f"no alias {alias!r}"), 404

    if existing_alias.get("Item").get("user") != flask.request.remote_user:
        return flask.jsonify(error="no touching"), 403

    resp = table.delete_item(Key=dict(alias=alias))
    log.debug(f"raw dynamodb response={resp!r}")

    return "", 204
