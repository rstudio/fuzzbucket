import flask
import flask_dance.consumer
import flask_login
import werkzeug.utils

from . import cfg, user
from .log import log

login_manager = flask_login.LoginManager()
login_manager.anonymous_user = user.User  # type: ignore
login_manager.login_view = "guts.login"  # type: ignore


@login_manager.request_loader
def load_user_from_request(request: flask.Request) -> user.User | None:
    user_id, source = _load_user_id_from_request(request)

    if user_id is None:
        log.warning("no user_id available in any source")

        return None

    lower_user = str(user_id).lower()

    if user_id != lower_user:
        user_id = lower_user

        log.debug("normalized user to lowercase", extra=dict(user_id=user_id))

    log.info("loading user", extra=dict(user_id=user_id, source=source))

    flask.session["user"] = user_id

    return user.User.load(user_id)


def _load_user_id_from_request(request: flask.Request) -> tuple[str | None, str]:
    log.debug(
        "loading user from session and request",
        extra=dict(
            session=flask.session,
            headers=request.headers,
            request_args=request.args,
            cookies=request.cookies,
        ),
    )

    for source_name, source, key in (
        ("session", flask.session, "user"),
        ("headers", request.headers, "fuzzbucket-user"),
        ("args", request.args, "user"),
    ):
        user_id: str | None = source.get(key)
        if user_id is not None:
            return user_id, source_name

    return None, ""


@login_manager.unauthorized_handler
def auth_403():
    login_url = ""

    with flask.current_app.app_context():
        login_url = flask.url_for(f"{get_oauth_blueprint().name}.login", _external=True)

    return (
        flask.jsonify(
            error=f"you must authorize first via {login_url!r}",
            login_url=login_url,
        ),
        403,
    )


def get_oauth_blueprint() -> flask_dance.consumer.OAuth2ConsumerBlueprint:
    if "oauth_blueprint" not in flask.g:
        oauth_blueprint_name = cfg.AUTH_PROVIDER.replace("-", "_")
        flask.g.oauth_blueprint = werkzeug.utils.import_string(
            f"fuzzbucket.blueprints.{oauth_blueprint_name}.bp"
        )

    return flask.g.oauth_blueprint
