import functools
import typing

import flask
import flask_dance.consumer.storage

from . import aws
from .log import log


class FlaskDanceStorage(flask_dance.consumer.storage.BaseStorage):
    def __init__(self, table_name: str | None) -> None:
        self.table_name = table_name

    def get(self, _) -> str | None:
        """fulfills the session storage method for getting the session token"""
        token = self.dump().get("token")

        log.debug(f"getting token={token!r}")

        return token

    def set(self, _, token) -> None:
        """fulfills the session storage method for setting the session token"""
        item = self.dump() | dict(token=token)

        if "user" not in item:
            raise ValueError("cannot set token without user")

        # NOTE: dynamodb is very upset about floats, so make sure a numeric
        # "expires_at" is an integer.
        if token is not None and "expires_at" in token:
            item["token"]["expires_at"] = int(token["expires_at"])

        log.debug(f"setting item={item!r} for user={item['user']!r}")

        self.table.put_item(Item=item)

    def delete(self, _) -> None:
        """fulfills the session storage method for deleting the session token"""
        user = self._load_user()
        log.debug(f"wiping record for user={user!r}")

        if user is None:
            raise ValueError("cannot delete record without user")

        # NOTE: this is a "soft delete" in that the user record is retained, but
        # all other fields are nullified. Anything more destructive will require
        # direct modification via dynamodb tools.
        self.table.put_item(Item=dict(user=user))

    @functools.cached_property
    def table(self):
        return aws.get_dynamodb().Table(self.table_name)

    @property
    def secret(self) -> str | None:
        return self.dump().get("secret")

    @secret.setter
    def secret(self, value: str) -> None:
        item = self.dump() | dict(secret=value)

        if "user" not in item:
            raise ValueError("cannot set secret without user")

        log.debug(f"setting item={item!r} for user={item['user']!r}")

        self.table.put_item(Item=item)

    def dump(self) -> dict:
        user = self._load_user()

        log.debug(f"dumping record user={user!r}")

        if user is None:
            return {}

        item: dict[str, typing.Any] = self.table.get_item(
            Key=dict(user=user),
            ConsistentRead=True,
        ).get(
            "Item",
            dict(user=user),
        )

        # NOTE: datetime is very upset about Decimal arguments to
        # utcfromtimestamp, so make sure a Decimal "expires_at" is an integer.
        if (
            "token" in item
            and item["token"] is not None
            and "expires_at" in item["token"]
        ):
            item["token"]["expires_at"] = int(item["token"]["expires_at"])

        log.debug(f"dumped record={item!r} user={user!r}")

        return item

    def _load_user(self) -> str | None:
        value = flask.session.get("user")

        if value is not None and value != str(value).lower():
            value = str(value).lower()
            log.debug(f"migrated session user to lowercase session user={value!r}")

        log.debug(f"storage fetched from session user={value!r}")

        return value
