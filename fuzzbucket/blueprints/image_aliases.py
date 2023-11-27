import flask
import flask_login

from .. import aws, cfg
from ..log import log

bp = flask.Blueprint("image_aliases", __name__)


@bp.route("/", methods=("GET",), strict_slashes=False)
@flask_login.login_required
def list_image_aliases():
    user_id: str | None = flask_login.current_user.get_id()

    if user_id is None:
        flask.abort(403)

    log.debug(f"handling list_image_aliases for user={user_id!r}")

    table = aws.get_dynamodb().Table(cfg.IMAGE_ALIASES_TABLE)

    image_aliases = {}
    for item in table.scan().get("Items", []):
        image_aliases[item["alias"]] = item["ami"]

    return (
        flask.jsonify(image_aliases=image_aliases, you=user_id),
        200,
    )


@bp.route("/", methods=("POST",), strict_slashes=False)
@flask_login.login_required
def create_image_alias():
    user_id: str | None = flask_login.current_user.get_id()

    if user_id is None:
        flask.abort(403)

    log.debug(f"handling create_image_alias for user={user_id!r}")

    if not flask.request.is_json:
        return flask.jsonify(error="request is not json"), 400

    assert flask.request.json is not None

    table = aws.get_dynamodb().Table(cfg.IMAGE_ALIASES_TABLE)
    resp = table.put_item(
        Item=dict(
            user=user_id,
            alias=flask.request.json["alias"],
            ami=flask.request.json["ami"],
        ),
    )

    log.debug(f"raw dynamodb response={resp!r}")

    return (
        flask.jsonify(
            image_aliases={flask.request.json["alias"]: flask.request.json["ami"]},
            you=user_id,
        ),
        201,
    )


@bp.route("/<string:alias>", methods=("DELETE",))
@flask_login.login_required
def delete_image_alias(alias):
    user_id: str | None = flask_login.current_user.get_id()

    if user_id is None:
        flask.abort(403)

    log.debug(f"handling delete_image_alias for user={user_id!r} alias={alias!r}")

    table = aws.get_dynamodb().Table(cfg.IMAGE_ALIASES_TABLE)

    existing_alias = table.get_item(Key=dict(alias=alias))
    if existing_alias.get("Item") in (None, {}):
        return flask.jsonify(error=f"no alias {alias!r}"), 404

    if existing_alias.get("Item").get("user") != user_id:
        return flask.jsonify(error="no touching"), 403

    resp = table.delete_item(Key=dict(alias=alias))
    log.debug(f"raw dynamodb response={resp!r}")

    return "", 204
