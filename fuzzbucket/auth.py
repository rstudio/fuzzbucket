import typing

import flask
import flask_dance.consumer
import flask_login
import oauthlib.oauth2.rfc6749.errors
from flask_dance.contrib.github import github

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

    log.info(f"loaded user_id={user_id!r} from source={source!r}")

    # FIXME: is this necessary for oauth session providers to work?
    flask.session["user"] = user_id

    if cfg.AUTH_PROVIDER == "github-oauth":
        if not github.authorized:
            log.debug("not currently github authorized; assuming login flow")

            return None

        user_response = github.get("/user").json()
        github_login = user_response.get("login")

        if github_login is None:
            log.warning(f"no login available in github user response={user_response!r}")

            return None

        if str(github_login).lower() == user_id:
            log.debug(
                f"github login={github_login!r} case-insensitive matches session"
                f" user={user_id!r}"
            )

            return user.User.load(user_id)

        log.warning(f"mismatched github_login={github_login!r} user={user_id!r}")

    elif cfg.AUTH_PROVIDER == "oauth":
        assert flask.current_app.config["oauth_blueprint"] is not None
        assert flask.current_app.config["oauth_blueprint"].session is not None

        if not flask.current_app.config["oauth_blueprint"].session.authorized:
            log.debug(
                f"not currently authorized; assuming login flow; "
                + f"session={flask.session!r}"
            )

            return None

        userinfo_response = _fetch_oauth_userinfo(
            flask.current_app.config["oauth_blueprint"].session,
            user_id,
        )
        if userinfo_response is None:
            return None

        log.debug(f"fetched userinfo={userinfo_response!r}")

        user_email = userinfo_response.get("email")
        if user_email is None:
            log.warning(
                f"no login available in oauth userinfo response={userinfo_response!r}"
            )

            return None

        if user_email.lower() == user_id:
            log.debug(
                f"oauth login={user_email!r} case-insensitive matches session "
                + f"user={user_id!r}"
            )

            return user.User.load(user_id)

        log.warning(
            f"mismatched user_email={user_email!r} user={user_id!r}; "
            + "wiping session user and token"
        )

    return None


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

    #   session_cookie = request.cookies.get("session")
    #   if session_cookie is None:
    #       return None, ""

    return None, ""


@login_manager.unauthorized_handler
def auth_403():
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


def _fetch_oauth_userinfo(
    oauth_session: flask_dance.consumer.OAuth2Session,
    user_id: str | None,
) -> dict[str, typing.Any] | None:
    assert oauth_session is not None
    assert oauth_session.token is not None
    assert user_id is not None

    try:
        return oauth_session.get("userinfo").json()
    except oauthlib.oauth2.rfc6749.errors.OAuth2Error:
        log.exception(f"failed to get oauth userinfo for user={user_id}")

        return None
