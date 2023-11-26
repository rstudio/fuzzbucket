import base64
import typing

import boto3
import moto
import pytest

import conftest
from fuzzbucket import auth, aws, blueprints


@pytest.mark.parametrize(
    ("authd", "expected"),
    [
        pytest.param(
            True,
            200,
            id="happy",
        ),
        pytest.param(False, 403, id="forbidden"),
    ],
)
@moto.mock_dynamodb
def test_list_image_aliases(
    app, authd_headers, fake_oauth_session, monkeypatch, authd, expected
):
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: authd)
    fake_oauth_session.authorized = authd
    monkeypatch.setattr(auth, "github", fake_oauth_session)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    with app.test_client() as c:
        response = c.get("/image-alias/", headers=authd_headers)
        assert response is not None
        assert response.status_code == expected


@pytest.mark.parametrize(
    ("authd", "expected"),
    [
        pytest.param(
            True,
            201,
            id="happy",
        ),
        pytest.param(False, 403, id="forbidden"),
    ],
)
@moto.mock_dynamodb
def test_create_image_alias(
    app, authd_headers, fake_oauth_session, monkeypatch, authd, expected
):
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: authd)
    fake_oauth_session.authorized = authd
    monkeypatch.setattr(auth, "github", fake_oauth_session)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    with app.test_client() as c:
        response = c.post(
            "/image-alias/",
            json={"alias": "yikes", "ami": "ami-fafababacaca"},
            headers=authd_headers,
        )
        assert response is not None
        assert response.status_code == expected


@moto.mock_dynamodb
def test_create_image_alias_not_json(
    app, authd_headers, fake_oauth_session, monkeypatch
):
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: True)
    monkeypatch.setattr(auth, "github", fake_oauth_session)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    with app.test_client() as c:
        response = c.post(
            "/image-alias/",
            data="HAY",
            headers=authd_headers,
        )
        assert response is not None
        assert response.status_code == 400


@pytest.mark.parametrize(
    ("authd", "expected"),
    [pytest.param(True, 204, id="happy"), pytest.param(False, 403, id="forbidden")],
)
@moto.mock_dynamodb
def test_delete_image_alias(
    app, authd_headers, fake_oauth_session, monkeypatch, authd, expected
):
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: authd)
    fake_oauth_session.authorized = authd
    monkeypatch.setattr(auth, "github", fake_oauth_session)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    with app.test_client() as c:
        response = c.delete("/image-alias/ubuntu18", headers=authd_headers)
        assert response is not None
        assert response.status_code == expected


@moto.mock_dynamodb
def test_delete_image_alias_no_alias(
    app, fake_oauth_session, authd_headers, monkeypatch
):
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: True)
    monkeypatch.setattr(auth, "github", fake_oauth_session)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    with app.test_client() as c:
        response = c.delete("/image-alias/nah", headers=authd_headers)
        assert response is not None
        assert response.status_code == 404


@moto.mock_dynamodb
def test_delete_image_alias_not_yours(app, fake_oauth_session, monkeypatch):
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: True)
    monkeypatch.setattr(auth, "github", fake_oauth_session)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    with app.test_client() as c:
        response = c.delete(
            "/image-alias/ubuntu18",
            headers=[("Authorization", base64.b64encode(b"jag:wagon").decode("utf-8"))],
        )
        assert response is not None
        assert response.status_code == 403
        assert "error" in typing.cast(conftest.AnyDict, response.json)
        assert typing.cast(conftest.AnyDict, response.json)["error"] == "no touching"
