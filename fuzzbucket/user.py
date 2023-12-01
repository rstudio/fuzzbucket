import dataclasses
import typing

import flask

from . import g
from .log import log


@dataclasses.dataclass
class User:
    user_id: str | None = None
    token: dict[str, typing.Any] | None = dataclasses.field(repr=False, default=None)
    secret: str | None = dataclasses.field(repr=False, default=None)

    @classmethod
    def load(cls, user_id: str | None) -> "User":
        user_dict = {}

        with flask.current_app.app_context():
            user_dict = g.user_storage.dump(user_id)  # type: ignore

        inst = cls(
            user_id=user_dict.get("user"),
            token=user_dict.get("token"),
            secret=user_dict.get("secret"),
        )

        log.debug("loaded", extra=dict(user=inst))

        return inst

    @property
    def is_authenticated(self):
        log.debug("in is_authenticated", extra=dict(user_id=self.user_id))

        if self.user_id is None or not g.oauth_session.authorized:
            log.debug(
                "in is_authenticated not authd via oauth",
                extra=dict(user_id=self.user_id, provider=g.oauth_blueprint.name),
            )

            return False

        log.debug(
            "in is_authenticated considering request path",
            extra=dict(path=flask.request.path, user_id=self.user_id),
        )

        if flask.request.path.endswith("/auth-complete"):
            log.debug(
                "in is_authenticated at auth-complete path",
                extra=dict(result=True, user_id=self.user_id),
            )

            return True

        headers_secret = flask.request.headers.get("fuzzbucket-secret")
        db_secret = g.user_storage.secret
        value = headers_secret == db_secret

        if headers_secret is None:
            log.debug(
                "in is_authenticated missing headers secret",
                extra=dict(result=False, user_id=self.user_id),
            )

            return False

        log.debug(
            "in is_authenticated comparing secrets",
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
            "in is_active",
            extra=dict(user_id=self.user_id, secret=_kinda_redacted(self.secret)),
        )

        return self.secret is not None

    @property
    def is_anonymous(self):
        log.debug("in is_anonymous", extra=dict(user_id=self.user_id))

        return self.user_id is None

    def get_id(self):
        log.debug("in get_id", extra=dict(user_id=self.user_id))

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

        log.debug("in as_item", extra=dict(item=item))

        return item


def _kinda_redacted(value: str | None) -> str:
    if value is None or len(value) < 13:
        return "..."

    return value[:3] + "..." + value[-3:]
