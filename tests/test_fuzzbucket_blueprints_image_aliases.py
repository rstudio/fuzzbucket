import typing

import pytest

import conftest
from fuzzbucket import user


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
def test_list_image_aliases(
    app,
    dynamodb,
    fake_users,
    fake_oauth_session,
    authd,
    expected,
):
    fake_oauth_session.authorized = authd

    with app.test_client(user=(user.User.load("pytest") if authd else None)) as c:
        response = c.get(
            "/image-alias/",
            headers={
                "fuzzbucket-user": "pytest",
                "fuzzbucket-secret": fake_users.get("pytest", ""),
            },
        )
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
def test_create_image_alias(
    app,
    dynamodb,
    fake_users,
    fake_oauth_session,
    authd,
    expected,
):
    fake_oauth_session.authorized = authd

    with app.test_client(user=(user.User.load("pytest") if authd else None)) as c:
        response = c.post(
            "/image-alias/",
            json={"alias": "yikes", "ami": "ami-fafababacaca"},
            headers={
                "fuzzbucket-user": "pytest",
                "fuzzbucket-secret": fake_users.get("pytest", ""),
            },
        )
        assert response is not None
        assert response.status_code == expected


def test_create_image_alias_not_json(
    app,
    dynamodb,
    fake_users,
    fake_oauth_session,
):
    with app.test_client(user=user.User.load("pytest")) as c:
        response = c.post(
            "/image-alias/",
            data="HAY",
            headers={
                "fuzzbucket-user": "pytest",
                "fuzzbucket-secret": fake_users.get("pytest", ""),
            },
        )
        assert response is not None
        assert response.status_code == 400


@pytest.mark.parametrize(
    ("authd", "expected"),
    [pytest.param(True, 204, id="happy"), pytest.param(False, 403, id="forbidden")],
)
def test_delete_image_alias(
    app,
    dynamodb,
    fake_users,
    fake_oauth_session,
    authd,
    expected,
):
    fake_oauth_session.authorized = authd

    with app.test_client(user=(user.User.load("pytest") if authd else None)) as c:
        response = c.delete(
            "/image-alias/ubuntu18",
            headers={
                "fuzzbucket-user": "pytest",
                "fuzzbucket-secret": fake_users.get("pytest", ""),
            },
        )
        assert response is not None
        assert response.status_code == expected


def test_delete_image_alias_no_alias(
    app,
    dynamodb,
    fake_users,
    fake_oauth_session,
):
    with app.test_client(user=user.User.load("pytest")) as c:
        response = c.delete(
            "/image-alias/nah",
            headers={
                "fuzzbucket-user": "pytest",
                "fuzzbucket-secret": fake_users.get("pytest", ""),
            },
        )
        assert response is not None
        assert response.status_code == 404


def test_delete_image_alias_not_yours(
    app,
    dynamodb,
    fake_users,
    fake_oauth_session,
):
    fake_oauth_session.responses["/user"]["login"] = "charizard"

    with app.test_client(user=user.User.load("charizard")) as c:
        response = c.delete(
            "/image-alias/ubuntu18",
            headers={
                "fuzzbucket-user": "charizard",
                "fuzzbucket-secret": fake_users.get("charizard", ""),
            },
        )
        assert response is not None
        assert response.status_code == 403
        assert "error" in typing.cast(conftest.AnyDict, response.json)
        assert typing.cast(conftest.AnyDict, response.json)["error"] == "no touching"
