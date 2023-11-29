import secrets
import typing

import flask
import flask_dance.consumer
import flask_login
import oauthlib.oauth2.rfc6749.errors

from .. import cfg, flask_dance_storage, user
from ..log import log

storage = flask_dance_storage.FlaskDanceStorage(table_name=cfg.USERS_TABLE)

bp = flask_dance.consumer.OAuth2ConsumerBlueprint(
    "oauth",
    __name__,
    base_url=cfg.get("FUZZBUCKET_OAUTH_BASE_URL"),
    client_id=cfg.get("FUZZBUCKET_OAUTH_CLIENT_ID"),
    client_secret=cfg.get("FUZZBUCKET_OAUTH_CLIENT_SECRET"),
    authorization_url=cfg.get("FUZZBUCKET_OAUTH_AUTH_URL"),
    authorization_url_params={"max_age": int(cfg.OAUTH_MAX_AGE)},
    auto_refresh_url=cfg.get("FUZZBUCKET_OAUTH_TOKEN_URL"),
    token_url=cfg.get("FUZZBUCKET_OAUTH_TOKEN_URL"),
    redirect_to="oauth.auth_complete",
    scope=list(cfg.getlist("FUZZBUCKET_OAUTH_SCOPE")),
    storage=storage,
)


@flask_dance.consumer.oauth_authorized.connect_via(bp)
def oauth_logged_in(
    blueprint: flask_dance.consumer.OAuth2ConsumerBlueprint,
    token: dict[str, typing.Any] | None,
) -> bool:
    if not token:
        log.warning("failed to log in via oauth")

        return False

    userinfo_response = _fetch_oauth_userinfo(blueprint.session)
    if userinfo_response is None:
        log.warning("failed to fetch user info")

        return False

    log.debug(f"fetched user info={userinfo_response!r}")

    user_email = userinfo_response.get("email")

    if user_email is None:
        log.warning("no login available in oauth userinfo response")

        return False

    log.debug(f"using user email={user_email!r}")

    fb_user = user.User.load(user_email)
    fb_user.token = token
    fb_user.secret = secrets.token_urlsafe(cfg.SECRET_TOKEN_SIZE_PLAIN)

    storage.save(fb_user.as_item())

    flask_login.login_user(fb_user)
    log.info(f"successfully signed in with user={fb_user.user_id!r}")

    return False


def _fetch_oauth_userinfo(
    oauth_session: flask_dance.consumer.OAuth2Session,
) -> dict[str, typing.Any] | None:
    assert oauth_session is not None
    assert oauth_session.token is not None

    try:
        return oauth_session.get("userinfo").json()
    except oauthlib.oauth2.rfc6749.errors.OAuth2Error:
        log.exception("failed to get oauth userinfo")

        return None


@flask_dance.consumer.oauth_error.connect_via(bp)
def oauth_error(
    blueprint: flask_dance.consumer.OAuth2ConsumerBlueprint,
    error: str | None = None,
    error_description: str | None = None,
    error_uri: str | None = None,
) -> None:
    log.error(
        "error during oauth",
        extra=dict(
            error=error, error_description=error_description, error_uri=error_uri
        ),
    )
    log.debug("session", extra=dict(session=blueprint.session))


@bp.route("/auth-complete", methods=("GET",))
@flask_login.login_required
def auth_complete():
    fb_user = user.User.load(flask.session["user"])

    return (
        flask.render_template(
            "auth_complete.html",
            branding=cfg.BRANDING,
            secret=fb_user.secret,
        ),
        200,
    )
