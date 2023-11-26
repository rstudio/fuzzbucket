import flask
from flask_dance.contrib.github import github

from . import cfg
from .log import log


def nullify_auth():
    log.debug(f"nullifying auth for user={flask.session.get('user')!r}")

    if cfg.AUTH_PROVIDER == "github-oauth":
        github.token = None

    elif cfg.AUTH_PROVIDER == "oauth":
        assert flask.current_app.config["oauth_blueprint"] is not None
        flask.current_app.config["oauth_blueprint"].session.token = None

    else:
        raise cfg.UNKNOWN_AUTH_PROVIDER

    del flask.session["user"]


def is_fully_authd():
    if cfg.AUTH_PROVIDER == "github-oauth":
        if not github.authorized:
            log.debug(
                f"github context not authorized for user={flask.session['user']!r}"
            )

            return False

        session_user_lower = str(flask.session["user"]).lower()
        github_login_lower = str(github.get("/user").json()["login"]).lower()

        if session_user_lower != github_login_lower:
            log.debug(
                f"session user={session_user_lower!r} does not match github"
                f" login={github_login_lower}"
            )

            return False

    elif cfg.AUTH_PROVIDER == "oauth":
        assert flask.current_app.config["oauth_blueprint"] is not None

        if not flask.current_app.config["oauth_blueprint"].session.authorized:
            log.debug(
                f"oauth context not authorized for user={flask.session['user']!r}"
            )

            return False

    else:
        raise cfg.UNKNOWN_AUTH_PROVIDER

    header_secret = flask.request.headers.get("Fuzzbucket-Secret")
    storage_secret = flask.current_app.config["session_storage"].secret

    if header_secret != storage_secret:
        log.debug(
            f"header secret={header_secret!r} does not match stored "
            f"secret={storage_secret!r}"
        )

        return False

    return True


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
