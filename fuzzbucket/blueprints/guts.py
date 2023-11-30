import json

import flask
import flask_login

from .. import aws, cfg, g
from ..log import log

bp = flask.Blueprint("guts", __name__)


@bp.app_errorhandler(500)
def handle_500(exc):
    log.debug("in handle_500", extra=dict(error=exc))

    if getattr(exc, "original_exception", None) is not None:
        exc = exc.original_exception

    if hasattr(exc, "get_response"):
        response = exc.get_response()

        if response is not None and response.is_json:
            return json.dumps(dict(error=str(exc))), 500

    return (
        flask.render_template(
            "error.html",
            branding=cfg.BRANDING,
            error=f"NOPE={exc}",
        ),
        500,
    )


@bp.after_app_request
def set_default_headers(resp: flask.Response) -> flask.Response:
    for key, value in cfg.DEFAULT_HEADERS:
        resp.headers[key] = value

    return resp


@bp.route("/whoami", methods=("GET",))
@flask_login.login_required
def whoami():
    return flask.jsonify(you=flask.session.get("user")), 200


@bp.route("/_login", methods=("GET",))
def login():
    redirect_to = flask.url_for(f"{g.oauth_blueprint.name}.login")

    log.debug(
        "handling login via redirect",
        extra=dict(
            redirect_to=redirect_to,
            session=flask.session,
        ),
    )

    return flask.redirect(redirect_to)


@bp.route("/_logout", methods=("POST",))
@flask_login.login_required
def logout():
    user_id: str = flask_login.current_user.get_id()

    log.debug("in logout", extra=dict(user=user_id))

    table = aws.get_dynamodb().Table(cfg.USERS_TABLE)
    existing_user = table.get_item(Key=dict(user=user_id))

    if existing_user.get("Item") in (None, {}):
        flask_login.logout_user()

        return flask.jsonify(error=f"no user {existing_user!r}"), 404

    resp = table.delete_item(Key=dict(user=user_id))
    log.debug("raw dynamodb response", extra=dict(resp=resp))

    flask_login.logout_user()

    return "", 204
