import json
import secrets

import flask
import flask_login
from flask_dance.contrib.github import github

from .. import aws, cfg
from ..log import log

bp = flask.Blueprint("guts", __name__)


@bp.app_errorhandler(500)
def handle_500(exc):
    log.debug(f"handling internal server error={exc!r}")

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
    redirect_to: str = ""

    if cfg.AUTH_PROVIDER == "github-oauth":
        redirect_to = flask.url_for("github.login")
    elif cfg.AUTH_PROVIDER == "oauth":
        redirect_to = flask.url_for("oauth.login")
    else:
        raise cfg.UNKNOWN_AUTH_PROVIDER

    log.debug(
        f"handling login via redirect to {redirect_to!r}; session={flask.session!r}"
    )

    return flask.redirect(redirect_to)


@bp.route("/auth-complete", methods=("GET",))
@flask_login.login_required
def github_auth_complete():
    log.debug(f"allowed_orgs={cfg.ALLOWED_GITHUB_ORGS!r}")

    raw_user_orgs = github.get("/user/orgs").json()
    log.debug(f"raw_user_orgs={raw_user_orgs!r}")

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

    return _set_secret_auth_complete()


@bp.route("/oauth-complete", methods=("GET",))
@flask_login.login_required
def oauth_complete():
    assert flask.current_app.config["oauth_blueprint"] is not None
    assert flask.current_app.config["oauth_blueprint"].session is not None

    return _set_secret_auth_complete()


def _set_secret_auth_complete():
    try:
        secret = secrets.token_urlsafe(31)
        flask.current_app.config["session_storage"].secret = secret

        return (
            flask.render_template(
                "auth_complete.html",
                branding=cfg.BRANDING,
                secret=secret,
            ),
            200,
        )
    except ValueError:
        log.exception(f"failed to set secret for user={flask.session.get('user')!r}")

        return (
            flask.render_template(
                "error.html",
                branding=cfg.BRANDING,
                error=f"Failed to set secret for user={flask.session.get('user')!r}",
            ),
            500,
        )


@bp.route("/_logout", methods=("POST",))
@flask_login.login_required
def logout():
    user_id: str | None = flask_login.current_user.get_id()

    if user_id is None:
        flask_login.logout_user()

        flask.abort(403)

    log.debug(f"handling _logout for user={user_id!r}")

    table = aws.get_dynamodb().Table(cfg.USERS_TABLE)
    existing_user = table.get_item(Key=dict(user=user_id))

    if existing_user.get("Item") in (None, {}):
        flask_login.logout_user()

        return flask.jsonify(error=f"no user {existing_user!r}"), 404

    resp = table.delete_item(Key=dict(user=user_id))
    log.debug(f"raw dynamodb response={resp!r}")

    flask_login.logout_user()

    return "", 204
