import secrets
import typing

import flask
import flask_dance.consumer
import flask_dance.contrib.github
import flask_login

from .. import cfg, flask_dance_storage, user
from ..log import log

storage = flask_dance_storage.FlaskDanceStorage(table_name=cfg.USERS_TABLE)

bp = flask_dance.contrib.github.make_github_blueprint(
    scope= "read:org,read:public_key",
    redirect_to="github.auth_complete",
    storage=storage,
)


@flask_dance.consumer.oauth_authorized.connect_via(bp)
def github_logged_in(
    blueprint: flask_dance.consumer.OAuth2ConsumerBlueprint,
    token: dict[str, typing.Any] | None,
) -> bool:
    if not token:
        log.warning("failed to log in via github oauth")

        return False

    resp = blueprint.session.get("/user")
    if not resp.ok:
        log.warning(
            "failed to fetch user info from github", extra=dict(status=resp.status)
        )

        return False

    user_response = resp.json()
    github_login = user_response.get("login")

    if github_login is None:
        log.warning("no login found in github user response")

        return False

    log.debug("using github login", extra=dict(login=github_login))

    fb_user = user.User.load(github_login)
    fb_user.token = token
    fb_user.secret = secrets.token_urlsafe(cfg.SECRET_TOKEN_SIZE_PLAIN)

    storage.save(fb_user.as_item())

    flask_login.login_user(fb_user)
    log.info("successfully signed in with github", extra=dict(user=fb_user.user_id))

    return False


@flask_dance.consumer.oauth_error.connect_via(bp)
def oauth_error(
    blueprint: flask_dance.consumer.OAuth2ConsumerBlueprint,
    error: str | None = None,
    error_description: str | None = None,
    error_uri: str | None = None,
) -> None:
    log.error(
        "in oauth_error during github oauth",
        extra=dict(
            error=error, error_description=error_description, error_uri=error_uri
        ),
    )
    log.debug("in oauth_error with session", extra=dict(session=blueprint.session))


@bp.route("/auth-complete", methods=("GET",))
@flask_login.login_required
def auth_complete():
    log.debug(
        "in github.auth_complete", extra=dict(allowed_orgs=cfg.ALLOWED_GITHUB_ORGS)
    )

    raw_user_orgs = flask_dance.contrib.github.github.get("/user/orgs").json()
    log.debug(
        "in github.auth_complete with raw_user_orgs",
        extra=dict(raw_user_orgs=raw_user_orgs),
    )

    if "message" in raw_user_orgs:
        return (
            flask.render_template(
                "error.html",
                branding=cfg.BRANDING,
                error=f"GitHub API error: {raw_user_orgs['message']}",
            ),
            503,
        )

    user_orgs = {o["login"] for o in raw_user_orgs}

    if len(set(cfg.ALLOWED_GITHUB_ORGS) & user_orgs) == 0:
        flask_login.logout_user()

        return (
            flask.render_template(
                "error.html",
                branding=cfg.BRANDING,
                error="You are not a member of an allowed GitHub organization.",
            ),
            403,
        )

    fb_user = user.User.load(flask.session["user"])

    return (
        flask.render_template(
            "auth_complete.html",
            branding=cfg.BRANDING,
            secret=fb_user.secret,
        ),
        200,
    )
