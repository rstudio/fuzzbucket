import flask
import flask_login

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

        log.debug(f"normalized user to lowercase user_id={user_id!r}")

    log.info(f"loading user with user_id={user_id!r} from source={source!r}")

    flask.session["user"] = user_id

    return user.User.load(user_id)


def _load_user_id_from_request(request: flask.Request) -> tuple[str | None, str]:
    log.debug(
        f"loading user from session={flask.session!r} and request "
        + f"headers={request.headers!r} args={request.args!r} "
        + f"cookies={request.cookies!r}"
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
    # TODO: get oauth blueprint redirect URL directly from app.config
    if cfg.AUTH_PROVIDER == "github-oauth":
        login_url = flask.url_for("github.login", _external=True)
        return (
            flask.jsonify(
                error=f"you must authorize first via {login_url!r}",
                login_url=login_url,
            ),
            403,
        )

    elif cfg.AUTH_PROVIDER == "oauth":
        login_url = flask.url_for("oauth.login", _external=True)
        return (
            flask.jsonify(
                error=f"you must authorize first via {login_url!r}",
                login_url=login_url,
            ),
            403,
        )

    else:
        raise cfg.UNKNOWN_AUTH_PROVIDER
