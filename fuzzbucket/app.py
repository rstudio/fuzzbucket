import warnings

import flask
import flask.json.provider
import flask_dance.consumer

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

    app.config["GITHUB_OAUTH_CLIENT_ID"] = cfg.get("FUZZBUCKET_GITHUB_OAUTH_CLIENT_ID")
    app.config["GITHUB_OAUTH_CLIENT_SECRET"] = cfg.get(
        "FUZZBUCKET_GITHUB_OAUTH_CLIENT_SECRET"
    )

    oauth_bp: flask_dance.consumer.OAuth2ConsumerBlueprint | None = None

    if cfg.AUTH_PROVIDER == "github-oauth":
        from .blueprints.github_oauth import bp as oauth_bp
    elif cfg.AUTH_PROVIDER == "oauth":
        from .blueprints.oauth import bp as oauth_bp
    else:
        warnings.warn(f"unknown auth provider {cfg.AUTH_PROVIDER!r}")

    assert oauth_bp is not None

    app.config["oauth_blueprint"] = oauth_bp
    app.register_blueprint(oauth_bp, url_prefix="/login")

    auth.login_manager.init_app(app)

    flask.request_started.connect(_log_request_started, app)
    flask.request_finished.connect(_log_request_finished, app)

    return app


def _log_request_started(*_, **__):
    log.debug(f"request started {flask.request}")


def _log_request_finished(_, response: flask.Response):
    log.debug(f"request finished {flask.request} response={response!r}")
