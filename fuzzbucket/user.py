import dataclasses
import typing

import flask
import flask_dance.consumer
from flask_dance.contrib.github import github

from . import cfg, flask_dance_storage
from .log import log

# FIXME: use LocalProxy or put these in flask.g? {{
storage = flask_dance_storage.FlaskDanceStorage(cfg.USERS_TABLE)
_session: flask_dance.consumer.OAuth2ConsumerBlueprint | None = None
# }}


@dataclasses.dataclass
class User:
    user_id: str | None = None
    token: dict[str, typing.Any] | None = dataclasses.field(repr=False, default=None)
    secret: str | None = dataclasses.field(repr=False, default=None)

    @classmethod
    def load(cls, user_id: str | None) -> "User":
        user_dict = storage.dump(user_id)

        inst = cls(
            user_id=user_dict.get("user"),
            token=user_dict.get("token"),
            secret=user_dict.get("secret"),
        )

        log.debug("loaded", extra=dict(user=inst))

        return inst

    @property
    def is_authenticated(self):
        log.debug("handling", extra=dict(user_id=self.user_id))

        if cfg.AUTH_PROVIDER == "github-oauth":
            if (
                not github.authorized
                or self.user_id is None
                or (
                    self.user_id.lower()
                    != str(github.get("/user").json()["login"]).lower()
                )
            ):
                log.debug(
                    "via github oauth", extra=dict(result=False, user_id=self.user_id)
                )

                return False

        elif cfg.AUTH_PROVIDER == "oauth":
            if (
                self.user_id is None
                or not (
                    _session or flask.current_app.config["oauth_blueprint"].session
                ).authorized
            ):
                log.debug("via oauth", extra=dict(result=False, user_id=self.user_id))

                return False
        else:
            log.debug(
                "unknown provider", extra=dict(result=False, user_id=self.user_id)
            )

            return False

        log.debug(
            "considering request",
            extra=dict(path=flask.request.path, user_id=self.user_id),
        )

        if flask.request.path.endswith("/auth-complete"):
            log.debug("at auth-complete", extra=dict(result=True, user_id=self.user_id))

            return True

        headers_secret = flask.request.headers.get("fuzzbucket-secret")
        db_secret = flask.current_app.config["session_storage"].secret
        value = headers_secret == db_secret

        if headers_secret is None:
            log.debug(
                "missing headers secret", extra=dict(result=False, user_id=self.user_id)
            )

            return False

        log.debug(
            "comparing secrets",
            extra=dict(
                result=value,
                user_id=self.user_id,
                headers_secret=_kinda_redacted(headers_secret),
                db_secret=_kinda_redacted(db_secret),
            ),
        )

        return value

    @property
    def is_active(self):
        log.debug(
            "handling",
            extra=dict(user_id=self.user_id, secret=_kinda_redacted(self.secret)),
        )

        return self.secret is not None

    @property
    def is_anonymous(self):
        log.debug(f"handling", extra=dict(user_id=self.user_id))

        return self.user_id is None

    def get_id(self):
        log.debug("handling", extra=dict(user_id=self.user_id))

        return self.user_id

    def as_item(self) -> dict[str, typing.Any]:
        """return a dict that is suitable for use as a dynamodb item"""

        item: dict[str, typing.Any] = dict(
            user=self.user_id,
            token=self.token,
            secret=self.secret,
        )

        # NOTE: dynamodb is very upset about floats, so make sure numeric
        # "expires_at" and "expires_in" are integers.
        if item["token"] is not None:
            for key in ("expires_at", "expires_in"):
                if key in item["token"]:
                    item["token"][key] = int(item["token"][key])

        log.debug("handling", extra=dict(item=item))

        return item


def _kinda_redacted(value: str | None) -> str:
    if value is None or len(value) < 13:
        return "..."

    return value[:3] + "..." + value[-3:]
