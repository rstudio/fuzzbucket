import warnings

import flask
import flask.json.provider

from . import auth, cfg, flask_dance_storage, json_provider
from .blueprints import boxes, guts, image_aliases, keys
from .log import log


def create_app() -> flask.Flask:
    log.debug("creating app")

    app = flask.Flask(__name__)

    app.register_blueprint(guts.bp)
    app.register_blueprint(boxes.bp, url_prefix="/box")
    app.register_blueprint(image_aliases.bp, url_prefix="/image-alias")
    app.register_blueprint(keys.bp, url_prefix="/key")

    # NOTE: these URL rules are for backward compatibility with lower versions
    # of fuzzbucket-client:
    app.add_url_rule("/reboot/<string:instance_id>", "boxes.reboot_box")
    app.add_url_rule("/keys", "keys.list_keys")

    app.secret_key = cfg.get("FUZZBUCKET_FLASK_SECRET_KEY")
    app.json = json_provider.AsJSONProvider(app)

    session_storage = flask_dance_storage.FlaskDanceStorage(
        table_name=f"fuzzbucket-{cfg.STAGE}-users"
    )
    app.config["session_storage"] = session_storage

    if cfg.AUTH_PROVIDER == "github-oauth":
        from flask_dance.contrib.github import make_github_blueprint

        app.config["GITHUB_OAUTH_CLIENT_ID"] = cfg.get(
            "FUZZBUCKET_GITHUB_OAUTH_CLIENT_ID"
        )
        app.config["GITHUB_OAUTH_CLIENT_SECRET"] = cfg.get(
            "FUZZBUCKET_GITHUB_OAUTH_CLIENT_SECRET"
        )
        oauth_blueprint = make_github_blueprint(
            scope=["read:org", "read:public_key"],
            redirect_to="github_auth_complete",
            storage=session_storage,
        )
        app.config["oauth_blueprint"] = oauth_blueprint
        app.register_blueprint(oauth_blueprint, url_prefix="/login")

    elif cfg.AUTH_PROVIDER == "oauth":
        from flask_dance.consumer import OAuth2ConsumerBlueprint

        oauth_blueprint = OAuth2ConsumerBlueprint(
            "oauth",
            __name__,
            base_url=cfg.get("FUZZBUCKET_OAUTH_BASE_URL"),
            client_id=cfg.get("FUZZBUCKET_OAUTH_CLIENT_ID"),
            client_secret=cfg.get("FUZZBUCKET_OAUTH_CLIENT_SECRET"),
            authorization_url=cfg.get("FUZZBUCKET_OAUTH_AUTH_URL"),
            authorization_url_params={"max_age": int(cfg.OAUTH_MAX_AGE)},
            auto_refresh_url=cfg.get("FUZZBUCKET_OAUTH_TOKEN_URL"),
            token_url=cfg.get("FUZZBUCKET_OAUTH_TOKEN_URL"),
            redirect_to="guts.oauth_complete",
            scope=list(cfg.getlist("FUZZBUCKET_OAUTH_SCOPE")),
            storage=session_storage,
        )
        app.config["oauth_blueprint"] = oauth_blueprint
        app.register_blueprint(oauth_blueprint, url_prefix="/login")

    else:
        warnings.warn(f"unknown auth provider {cfg.AUTH_PROVIDER!r}")

    auth.login_manager.init_app(app)

    return app
