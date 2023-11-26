import boto3
import flask
import flask_dance.consumer
import flask_dance.contrib.github
import moto
import pytest

import conftest
from fuzzbucket import auth, cfg


@pytest.mark.parametrize(
    (
        "authd",
        "session_user",
        "user_response",
        "userinfo_response",
        "secret_header",
        "db_secret",
        "expected",
    ),
    [
        pytest.param(
            True,
            "pytest",
            {"login": "pytest"},
            {"email": "pytest@example.org"},
            "verysecret",
            "verysecret",
            True,
            id="happy",
        ),
        pytest.param(
            True,
            "pytest",
            {"login": "pytest"},
            {"email": "pytest@example.org"},
            "verysecret",
            "oh no",
            False,
            id="mismatched_db_secret",
        ),
        pytest.param(
            True,
            "pytest",
            {"login": "pytest"},
            {"email": "pytest@example.org"},
            "well then",
            "verysecret",
            False,
            id="mismatched_header_secret",
        ),
        pytest.param(
            False,
            "pytest",
            {"login": "pytest"},
            {"email": "pytest@example.org"},
            "verysecret",
            "verysecret",
            False,
            id="unauthorized",
        ),
    ]
    + (
        [
            pytest.param(
                True,
                "pytest",
                {"login": "founderman"},
                {"email": "pytest@example.org"},
                "verysecret",
                "verysecret",
                False,
                id="mismatched_user",
            ),
            pytest.param(
                True,
                "superperson",
                {"login": "pytest"},
                {"email": "pytest@example.org"},
                "verysecret",
                "verysecret",
                False,
                id="mismatched_session_user",
            ),
        ]
        if cfg.AUTH_PROVIDER == "github-oauth"
        else []
    ),
)
@moto.mock_dynamodb
def test_is_fully_authd(
    app,
    monkeypatch,
    fake_oauth_session,
    authd,
    session_user,
    user_response,
    userinfo_response,
    secret_header,
    db_secret,
    expected,
):
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)

    fake_oauth_session.responses["/user"] = user_response
    fake_oauth_session.responses["userinfo"] = userinfo_response
    fake_oauth_session.authorized = authd

    if cfg.AUTH_PROVIDER == "github-oauth":
        monkeypatch.setattr(flask_dance.contrib.github, "github", fake_oauth_session)
        monkeypatch.setattr(auth, "github", fake_oauth_session)

    elif cfg.AUTH_PROVIDER == "oauth":
        monkeypatch.setattr(
            app.config["oauth_blueprint"], "session", fake_oauth_session
        )

    monkeypatch.setattr(flask, "session", {"user": session_user})
    monkeypatch.setattr(
        flask,
        "request",
        conftest.FakeRequest({"Fuzzbucket-Secret": secret_header}, {}, {}),
    )

    def fake_dump(*_):
        return dict(user=session_user, secret=db_secret, token=None)

    monkeypatch.setattr(app.config["session_storage"], "dump", fake_dump)

    with app.app_context():
        assert auth.is_fully_authd() == expected
