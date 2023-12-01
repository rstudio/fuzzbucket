import flask
import flask.json.provider

from . import auth, cfg, g, json_provider
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
    app.add_url_rule("/", "boxes.list_boxes")
    app.add_url_rule("/reboot/<string:instance_id>", "boxes.reboot_box")
    app.add_url_rule("/keys", "keys.list_keys")

    app.url_map.strict_slashes = False

    app.secret_key = cfg.get("FUZZBUCKET_FLASK_SECRET_KEY")
    app.json = json_provider.AsJSONProvider(app)

    app.config["session_storage"] = g.user_storage

    with app.app_context():
        oauth_bp = auth.get_oauth_blueprint()
        app.register_blueprint(oauth_bp, url_prefix="/login")

        if oauth_bp.name == "github":
            app.config["GITHUB_OAUTH_CLIENT_ID"] = cfg.get(
                "FUZZBUCKET_GITHUB_OAUTH_CLIENT_ID"
            )
            app.config["GITHUB_OAUTH_CLIENT_SECRET"] = cfg.get(
                "FUZZBUCKET_GITHUB_OAUTH_CLIENT_SECRET"
            )

    auth.login_manager.init_app(app)

    flask.request_started.connect(_log_request_started, app)
    flask.request_finished.connect(_log_request_finished, app)

    return app


def _log_request_started(*_, **__):
    log.debug("request started", extra=dict(request=flask.request))


def _log_request_finished(_, response: flask.Response):
    log.debug("request finished", extra=dict(request=flask.request, response=response))
