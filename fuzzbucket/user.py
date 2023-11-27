import dataclasses
import typing

import flask
from flask_dance.contrib.github import github

from . import cfg, flask_dance_storage
from .log import log


@dataclasses.dataclass
class User:
    user_id: str | None = None
    token: dict[str, typing.Any] | None = None
    secret: str | None = None

    @classmethod
    def load(cls, user_id: str | None) -> "User":
        user = flask_dance_storage.FlaskDanceStorage(cfg.USERS_TABLE).dump(user_id)

        log.debug(f"loaded user={user!r}")

        return cls(
            user_id=user.get("user"),
            token=user.get("token"),
            secret=user.get("secret"),
        )

    @property
    def is_authenticated(self):
        if cfg.AUTH_PROVIDER == "github-oauth":
            if (
                not github.authorized
                or self.user_id is None
                or (
                    self.user_id.lower()
                    != str(github.get("/user").json()["login"]).lower()
                )
            ):
                return False

        elif cfg.AUTH_PROVIDER == "oauth":
            if (
                self.user_id is None
                or not flask.current_app.config["oauth_blueprint"].session.authorized
            ):
                return False
        else:
            return False

        return (
            flask.request.headers.get("fuzzbucket-secret")
            == flask.current_app.config["session_storage"].secret
        )

    @property
    def is_active(self):
        return self.secret is not None

    @property
    def is_anonymous(self):
        return self.user_id is None

    def get_id(self):
        return self.user_id
