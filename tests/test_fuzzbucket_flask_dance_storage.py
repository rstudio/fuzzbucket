import decimal
import os

import flask
import pytest

from fuzzbucket import aws, flask_dance_storage


def test_flask_dance_storage(dynamodb, monkeypatch):
    monkeypatch.setattr(flask, "session", {"user": "pytest"})

    table_name = f"fuzzbucket-{os.getenv('FUZZBUCKET_STAGE')}-users"
    storage = flask_dance_storage.FlaskDanceStorage(table_name)

    storage.set(None, {"token": "jagwagon8999"})
    storage.secret = "rotini"

    actual = storage.dump()

    for key, value in (
        ("user", "pytest"),
        ("token", {"token": "jagwagon8999"}),
        ("secret", "rotini"),
    ):
        assert key in actual
        assert actual[key] == value

    storage.set(None, {"token": "jagwagon9000", "expires_at": decimal.Decimal(14)})
    storage.secret = "farfalla"

    actual = storage.dump()

    for key, value in (
        ("user", "pytest"),
        ("token", {"token": "jagwagon9000", "expires_at": 14}),
        ("secret", "farfalla"),
    ):
        assert key in actual
        assert actual[key] == value

    storage.delete(None)

    assert storage.get(None) is None
    assert storage.secret is None

    with monkeypatch.context() as mp:
        mp.setattr(
            flask,
            "session",
            {"user": "Carbunkle"},
        )

        assert storage.dump() == {"user": "carbunkle"}

        def fake_load_user():
            return None

        mp.setattr(storage, "_load_user", fake_load_user)

        with pytest.raises(ValueError):
            storage.set(None, "busytown321")

        with pytest.raises(ValueError):
            storage.secret = "crungus"

        with pytest.raises(ValueError):
            storage.delete(None)

        assert storage.get(None) is None
        assert storage.secret is None
