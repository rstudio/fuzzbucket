import datetime
import decimal
import os
import random
import typing

import boto3
import flask
import moto
import pytest

import conftest
import fuzzbucket
import fuzzbucket.app
from fuzzbucket import (
    auth,
    aws,
    blueprints,
    box,
    cfg,
    datetime_ext,
    flask_dance_storage,
    reaper,
)


@pytest.mark.parametrize(
    ("authd", "session_user", "key_alias", "expected"),
    [
        pytest.param(
            True,
            "lordtestingham",
            "default",
            200,
            id="happy",
        ),
        pytest.param(
            True,
            "rumples",
            "chuckit",
            404,
            id="missing",
        ),
        pytest.param(False, "foible", "default", 403, id="forbidden"),
    ],
)
@moto.mock_ec2
@moto.mock_dynamodb
def test_get_key(
    app,
    authd_headers,
    fake_oauth_session,
    monkeypatch,
    authd,
    session_user,
    key_alias,
    expected,
):
    ec2_client = boto3.client("ec2")
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(aws, "get_ec2_client", lambda: ec2_client)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: authd)
    fake_oauth_session.authorized = authd
    fake_oauth_session.responses["/user"]["login"] = session_user
    monkeypatch.setattr(auth, "github", fake_oauth_session)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    fake_session = {"user": session_user}
    monkeypatch.setattr(flask, "session", fake_session)

    def fake_describe_key_pairs():
        return {
            "KeyPairs": [
                {
                    "KeyName": "lordTestingham",
                    "KeyPairId": "key-fafafafafafafafaf",
                    "KeyFingerprint": "ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa",
                }
            ]
        }

    monkeypatch.setattr(ec2_client, "describe_key_pairs", fake_describe_key_pairs)

    with app.test_client() as c:
        response = c.get(f"/key/{key_alias}", headers=authd_headers)

        assert response is not None
        assert response.status_code == expected

        if authd and expected < 400:
            assert response.json is not None
            assert "key" in response.json
            assert response.json["key"] is not None


@pytest.mark.parametrize(
    ("authd", "session_user", "n_keys", "expected"),
    [
        pytest.param(
            True,
            "lordtestingham",
            2,
            200,
            id="happy",
        ),
        pytest.param(
            True,
            "rumples",
            0,
            200,
            id="none",
        ),
        pytest.param(False, "foible", 0, 403, id="forbidden"),
    ],
)
@moto.mock_ec2
@moto.mock_dynamodb
def test_list_keys(
    app,
    authd_headers,
    fake_oauth_session,
    monkeypatch,
    authd,
    session_user,
    n_keys,
    expected,
):
    ec2_client = boto3.client("ec2")
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(aws, "get_ec2_client", lambda: ec2_client)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: authd)
    fake_oauth_session.authorized = authd
    fake_oauth_session.responses["/user"]["login"] = session_user
    monkeypatch.setattr(auth, "github", fake_oauth_session)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    fake_session = {"user": session_user}
    monkeypatch.setattr(flask, "session", fake_session)

    def fake_describe_key_pairs():
        return {
            "KeyPairs": [
                {
                    "KeyName": "lordTestingham",
                    "KeyPairId": "key-fafafafafafafafaf",
                    "KeyFingerprint": "ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa",
                },
                {
                    "KeyName": "lordTestingham-fancy",
                    "KeyPairId": "key-fafafafafafafafaf",
                    "KeyFingerprint": "ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa",
                },
            ]
        }

    monkeypatch.setattr(ec2_client, "describe_key_pairs", fake_describe_key_pairs)

    with app.test_client() as c:
        response = c.get("/key/", headers=authd_headers)
        assert response is not None
        assert response.status_code == expected

        if authd and expected < 400:
            assert response.json is not None
            assert "keys" in response.json
            assert response.json["keys"] is not None
            assert len(response.json["keys"]) == n_keys


@pytest.mark.parametrize(
    ("authd", "session_user", "key_alias", "request_kwargs", "expected"),
    [
        pytest.param(
            True,
            "philobuster",
            "fancy",
            dict(
                json={
                    "key_material": "".join(
                        [
                            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwZRcwdL1TLYM",
                            "sKT6oYiKHjME0iyQKl1mOIZNA2pGqOJ8IH7UPX4AocNhw1G5xzA",
                            "UG6FChZ32h8E+AMWjaJoOBnXSqlM3m1Up4KV0UsvPI5mVg/bm9j",
                            "iCQ5OkwReEkmSC0hPAsQ5ztSZlRmG6Yo343D1wISgKOcmGEOdJR",
                            "N26KiuIwSZ7LkMX1Uc1gIKaiNbTp8Jtn2nmB0O2R5Jvcsv5yICR",
                            "jvTYl11hiNEg+TOJRQBoeyC2tsYwkWoabShm4Oi4X/UjB5UNDhG",
                            "qQ/JX8XMyp0rFBIqTyd69csRoDqFJ2xGHYn+WmBbCHfyyks7LWz",
                            "aCJzdekMg2iEBE7eoodM86V oop",
                        ]
                    )
                }
            ),
            201,
            id="happy",
        ),
        pytest.param(
            True,
            "slimer",
            "default",
            dict(
                json={
                    "key_material": "".join(
                        [
                            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwZRcwdL1TLYM",
                            "sKT6oYiKHjME0iyQKl1mOIZNA2pGqOJ8IH7UPX4AocNhw1G5xzA",
                            "UG6FChZ32h8E+AMWjaJoOBnXSqlM3m1Up4KV0UsvPI5mVg/bm9j",
                            "iCQ5OkwReEkmSC0hPAsQ5ztSZlRmG6Yo343D1wISgKOcmGEOdJR",
                            "N26KiuIwSZ7LkMX1Uc1gIKaiNbTp8Jtn2nmB0O2R5Jvcsv5yICR",
                            "jvTYl11hiNEg+TOJRQBoeyC2tsYwkWoabShm4Oi4X/UjB5UNDhG",
                            "qQ/JX8XMyp0rFBIqTyd69csRoDqFJ2xGHYn+WmBbCHfyyks7LWz",
                            "aCJzdekMg2iEBE7eoodM86V oop",
                        ]
                    )
                }
            ),
            500,
            id="ec2_err",
        ),
        pytest.param(
            True,
            "philobuster",
            "fancy",
            dict(json={"key_material": "yuno"}),
            400,
            id="invalid_key_material",
        ),
        pytest.param(
            True,
            "philobuster",
            "fancy",
            dict(json={"key_material": ""}),
            400,
            id="empty_key_material",
        ),
        pytest.param(
            True,
            "philobuster",
            "fancy",
            dict(data="yuno"),
            400,
            id="not_json",
        ),
        pytest.param(
            True,
            "charizard",
            "default",
            dict(json={}),
            409,
            id="conflict",
        ),
        pytest.param(False, "morgenstern", "default", {}, 403, id="forbidden"),
    ],
)
@moto.mock_ec2
@moto.mock_dynamodb
def test_put_key(
    app,
    authd_headers,
    fake_oauth_session,
    monkeypatch,
    authd,
    session_user,
    key_alias,
    request_kwargs,
    expected,
):
    ec2_client = boto3.client("ec2")
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(aws, "get_ec2_client", lambda: ec2_client)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: authd)
    fake_oauth_session.authorized = authd
    fake_oauth_session.responses["/user"]["login"] = session_user
    monkeypatch.setattr(auth, "github", fake_oauth_session)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    fake_session = {"user": session_user}
    monkeypatch.setattr(flask, "session", fake_session)

    state = {"describe_key_pairs_call": 0}

    def fake_describe_key_pairs():
        key_pairs = {
            "0": {
                "KeyPairs": [
                    {
                        "KeyName": "charizard",
                        "KeyPairId": "key-fafafafafafafafaf",
                        "KeyFingerprint": "ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff"
                        + ":aa:ff:aa:ff:aa",
                    }
                ]
            },
            "1": {
                "KeyPairs": [
                    {
                        "KeyName": "charizard",
                        "KeyPairId": "key-fafafafafafafafaf",
                        "KeyFingerprint": "ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff"
                        + ":aa:ff:aa:ff:aa",
                    },
                    {
                        "KeyName": "philobuster-fancy",
                        "KeyPairId": "key-fafafafafafafafaf",
                        "KeyFingerprint": "ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff"
                        + ":aa:ff:aa:ff:aa",
                    },
                ]
            },
        }[str(state["describe_key_pairs_call"])]
        state["describe_key_pairs_call"] += 1
        return key_pairs

    monkeypatch.setattr(ec2_client, "describe_key_pairs", fake_describe_key_pairs)

    response = None
    with app.test_client() as c:
        response = c.put(f"/key/{key_alias}", headers=authd_headers, **request_kwargs)

    assert response is not None
    assert response.status_code == expected
    if authd and expected < 400:
        assert response.json is not None
        assert "key" in response.json
        assert response.json["key"] is not None


@pytest.mark.parametrize(
    ("authd", "session_user", "key_alias", "expected"),
    [
        pytest.param(
            True,
            "lordtestingham",
            "default",
            200,
            id="happy",
        ),
        pytest.param(
            True,
            "rumples",
            "chuckit",
            404,
            id="happy",
        ),
        pytest.param(False, "foible", "default", 403, id="forbidden"),
    ],
)
@moto.mock_ec2
@moto.mock_dynamodb
def test_delete_key(
    app,
    authd_headers,
    fake_oauth_session,
    monkeypatch,
    authd,
    session_user,
    key_alias,
    expected,
):
    ec2_client = boto3.client("ec2")
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(aws, "get_ec2_client", lambda: ec2_client)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: authd)
    fake_oauth_session.authorized = authd
    fake_oauth_session.responses["/user"]["login"] = session_user
    monkeypatch.setattr(auth, "github", fake_oauth_session)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    fake_session = {"user": session_user}
    monkeypatch.setattr(flask, "session", fake_session)

    def fake_describe_key_pairs():
        return {
            "KeyPairs": [
                {
                    "KeyName": "lordTestingham",
                    "KeyPairId": "key-fafafafafafafafaf",
                    "KeyFingerprint": "ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa",
                }
            ]
        }

    monkeypatch.setattr(ec2_client, "describe_key_pairs", fake_describe_key_pairs)

    with app.test_client() as c:
        response = c.delete(f"/key/{key_alias}", headers=authd_headers)

        assert response is not None
        assert response.status_code == expected

        if authd and expected < 400:
            assert response.json is not None
            assert "key" in response.json
            assert response.json["key"] is not None
