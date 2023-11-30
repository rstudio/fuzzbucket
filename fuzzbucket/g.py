import flask_dance.consumer
import werkzeug.local

from . import auth, flask_dance_storage

oauth_blueprint: werkzeug.local.LocalProxy[
    flask_dance.consumer.OAuth2ConsumerBlueprint
] = werkzeug.local.LocalProxy(auth.get_oauth_blueprint)

oauth_session: werkzeug.local.LocalProxy[
    flask_dance.consumer.OAuth2Session
] = werkzeug.local.LocalProxy(lambda: auth.get_oauth_blueprint().session)

user_storage: werkzeug.local.LocalProxy[
    flask_dance_storage.FlaskDanceStorage
] = werkzeug.local.LocalProxy(flask_dance_storage.get_storage)
