import secrets

import flask_dance.consumer.storage

from flask import session
from werkzeug.utils import cached_property

from . import NoneString, get_dynamodb, log


class FlaskDanceStorage(flask_dance.consumer.storage.BaseStorage):
    def __init__(self, table_name: NoneString) -> None:
        self.table_name = table_name

    @cached_property
    def table(self):
        return get_dynamodb().Table(self.table_name)

    def get(self, _) -> NoneString:
        return self.dump().get("token")

    def secret(self) -> NoneString:
        return self.dump().get("secret")

    def dump(self) -> dict:
        user = self._load_user()

        log.debug(f"dumping record user={user!r}")
        if user is None:
            return {}

        value = self.table.get_item(Key=dict(user=user)).get("Item", {}) or {}
        log.debug(f"dumped record={value!r} user={user!r}")

        return value

    def set(self, _, token) -> None:
        user = self._load_user()
        log.debug(f"setting token={token!r} for user={user!r}")

        if user is None:
            raise ValueError("no user found")

        self.table.put_item(
            Item=dict(user=user, token=token, secret=secrets.token_urlsafe(31))
        )

    def delete(self, _) -> None:
        user = self._load_user()
        log.debug(f"deleting token for user={user!r}")

        if user is None:
            raise ValueError("no user found")

        self.table.put_item(Item=dict(user=user))

    def _load_user(self) -> NoneString:
        value = session.get("user")
        if value is not None and value != str(value).lower():
            value = str(value).lower()
            log.debug(f"migrated session user to lowercase session user={value!r}")

        log.debug(f"storage fetched from session user={value!r}")

        return value
