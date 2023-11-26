import json
import secrets
import typing

import flask
import flask_dance.consumer
import oauthlib.oauth2.rfc6749.errors
from flask_dance.contrib.github import github

from .. import auth, aws, cfg
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


@bp.before_app_request
def set_user():
    source = "session"

    if flask.session.get("user") is None:
        user, source = flask.request.headers.get("Fuzzbucket-User"), "header"
        if user is None:
            user, source = flask.request.args.get("user"), "qs"

        flask.session["user"] = user

    if flask.session.get("user") is not None:
        lower_user = str(flask.session["user"]).lower()

        if flask.session["user"] != lower_user:
            flask.session["user"] = lower_user

            log.debug(
                f"migrated session user to lowercase session user={flask.session['user']!r}"
            )

    log.debug(
        f"setting remote_user from user={flask.session['user']!r} source={source!r}"
    )
    flask.request.environ["REMOTE_USER"] = flask.session["user"]

    if cfg.AUTH_PROVIDER == "github-oauth":
        if not github.authorized:
            log.debug("not currently github authorized; assuming login flow")

            return

        user_response = github.get("/user").json()
        github_login = user_response.get("login")

        if github_login is None:
            log.warning(f"no login available in github user response={user_response!r}")

            auth.nullify_auth()

            return

        if str(github_login).lower() == str(flask.session["user"]).lower():
            log.debug(
                f"github login={github_login!r} case-insensitive matches session"
                f" user={flask.session['user']!r}"
            )
            return

        log.warning(
            f"mismatched github_login={github_login!r} user={flask.session['user']!r}"
        )
        auth.nullify_auth()

    elif cfg.AUTH_PROVIDER == "oauth":
        assert flask.current_app.config["oauth_blueprint"] is not None
        assert flask.current_app.config["oauth_blueprint"].session is not None

        if not flask.current_app.config["oauth_blueprint"].session.authorized:
            log.debug("not currently authorized; assuming login flow")

            return

        userinfo_response = _fetch_oauth_userinfo(
            flask.current_app.config["oauth_blueprint"].session
        )
        if userinfo_response is None:
            auth.nullify_auth()

            return

        log.debug(f"fetched userinfo={userinfo_response!r}")

        user_email = userinfo_response.get("email")
        if user_email is None:
            log.warning(
                f"no login available in oauth userinfo response={userinfo_response!r}"
            )

            auth.nullify_auth()
            return

        if str(user_email).lower() == str(flask.session["user"]).lower():
            log.debug(
                f"oauth login={user_email!r} case-insensitive matches session "
                + f"user={flask.session['user']!r}"
            )
            return

        log.warning(
            f"mismatched user_email={user_email!r} user={flask.session['user']!r}; "
            + "wiping session user and token"
        )

        auth.nullify_auth()

    else:
        raise cfg.UNKNOWN_AUTH_PROVIDER


@bp.after_app_request
def set_default_headers(resp: flask.Response) -> flask.Response:
    for key, value in cfg.DEFAULT_HEADERS:
        resp.headers[key] = value

    return resp


def _fetch_oauth_userinfo(
    oauth_session: flask_dance.consumer.OAuth2Session,
) -> dict[str, typing.Any] | None:
    assert oauth_session is not None
    assert oauth_session.token is not None

    try:
        return oauth_session.get("userinfo").json()
    except oauthlib.oauth2.rfc6749.errors.OAuth2Error:
        log.exception(
            f"failed to get oauth userinfo for user={flask.session['user']!r}"
        )

        return None


@bp.route("/whoami", methods=("GET",))
def whoami():
    if not auth.is_fully_authd():
        return flask.jsonify(error="not logged in"), 400

    return flask.jsonify(you=flask.session.get("user")), 200


@bp.route("/_login", methods=("GET",))
def login():
    if cfg.AUTH_PROVIDER == "github-oauth":
        return flask.redirect(flask.url_for("github.login"))
    elif cfg.AUTH_PROVIDER == "oauth":
        return flask.redirect(flask.url_for("oauth.login"))
    else:
        raise cfg.UNKNOWN_AUTH_PROVIDER


@bp.route("/auth-complete", methods=("GET",))
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
        auth.nullify_auth()

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
def logout():
    if not auth.is_fully_authd():
        return flask.jsonify(error="not logged in"), 400

    log.debug(f"handling _logout for user={flask.request.remote_user!r}")

    table = aws.get_dynamodb().Table(f"fuzzbucket-{cfg.STAGE}-users")
    existing_user = table.get_item(Key=dict(user=flask.request.remote_user))

    if existing_user.get("Item") in (None, {}):
        return flask.jsonify(error=f"no user {existing_user!r}"), 404

    resp = table.delete_item(Key=dict(user=flask.request.remote_user))
    log.debug(f"raw dynamodb response={resp!r}")

    auth.nullify_auth()

    return "", 204
