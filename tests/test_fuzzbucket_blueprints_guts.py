import json
import re

import boto3
import flask
import moto
import pytest
import werkzeug.exceptions

import conftest
from fuzzbucket import auth, blueprints, cfg


@moto.mock_dynamodb
def test_login(app, monkeypatch, fake_oauth_session):
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)

    session = {}
    monkeypatch.setattr(flask, "session", session)

    fake_oauth_session.authorized = False
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    with app.test_client() as c:
        response = c.get("/_login?user=pytest")

        assert response is not None
        assert response.status_code == 302
        assert "Location" in response.headers
        assert "user" in session
        assert session["user"] == "pytest"


@pytest.mark.parametrize(
    ("authd", "session_user", "expected_status"),
    [
        pytest.param(True, "pytest", 204, id="happy"),
        pytest.param(False, "pytest", 400, id="not_logged_in"),
        pytest.param(True, "eggs", 404, id="unknown_user"),
    ],
)
@moto.mock_dynamodb
def test_logout(
    app, monkeypatch, authd, session_user, expected_status, fake_oauth_session
):
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)

    session = {"user": session_user}
    monkeypatch.setattr(flask, "session", session)

    fake_oauth_session.authorized = authd
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)
    monkeypatch.setattr(auth, "github", fake_oauth_session)

    monkeypatch.setattr(auth, "is_fully_authd", lambda: authd)

    with app.test_client() as c:
        response = c.post("/_logout")

        assert response is not None
        assert response.status_code == expected_status

        if expected_status == 204:
            assert "user" not in session


@pytest.mark.parametrize(
    ("allowed_orgs", "orgs_response", "raises", "expected"),
    [
        pytest.param(
            {"frobs", "globs"},
            [{"login": "frobs"}],
            False,
            conftest.TemplateResponse("auth_complete.html", 200),
            id="happy",
        ),
        pytest.param(
            {"frobs", "globs"},
            [],
            False,
            conftest.TemplateResponse("error.html", 403),
            id="forbidden",
        ),
        pytest.param(
            {"frobs", "globs"},
            {"message": "now you have gone and also done it"},
            False,
            conftest.TemplateResponse("error.html", 503),
            id="github_err",
        ),
        pytest.param(
            {"blubs", "glubs"},
            [{"login": "blubs"}],
            True,
            conftest.TemplateResponse("error.html", 500),
            id="no_secret_err",
        ),
    ],
)
@moto.mock_dynamodb
def test_auth_complete(
    app, monkeypatch, fake_oauth_session, allowed_orgs, orgs_response, raises, expected
):
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)

    state = {}

    def fake_render_template(template_name, **kwargs):
        state.update(template_name=template_name, kwargs=kwargs)
        return "RENDERED"

    monkeypatch.setattr(flask, "render_template", fake_render_template)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)
    monkeypatch.setattr(auth, "github", fake_oauth_session)
    monkeypatch.setattr(flask, "session", {"user": "pytest"})
    fake_oauth_session.responses["/user/orgs"] = orgs_response
    monkeypatch.setattr(cfg, "ALLOWED_GITHUB_ORGS", allowed_orgs)

    with app.test_client() as c:
        if raises:
            flask.session["user"] = None

        response = c.get("/auth-complete")

        assert response is not None
        assert not response.is_json
        assert response.status_code == expected.status_code
        assert state["template_name"] == expected.template_name


@pytest.mark.parametrize(
    ("exc", "check_html", "err_match"),
    [
        pytest.param(
            conftest.WrappedError(ValueError("not enough pylons")),
            True,
            "^NOPE=.*not enough pylons",
            id="wrapped",
        ),
        pytest.param(
            werkzeug.exceptions.InternalServerError(
                "spline reticulation overload",
                response=flask.Response(content_type="application/json"),
            ),
            False,
            ".*spline reticulation overload",
            id="wrapped_with_response",
        ),
        pytest.param(ValueError("whups"), True, "^NOPE.*whups", id="unhandled"),
    ],
)
def test_handle_500(monkeypatch, exc, check_html, err_match):
    state = {}

    def fake_render_template(template_name, **kwargs):
        state.update(template_name=template_name, kwargs=kwargs)
        return "RENDERED"

    monkeypatch.setattr(flask, "render_template", fake_render_template)

    if check_html:
        assert blueprints.guts.handle_500(exc) == ("RENDERED", 500)
        assert "kwargs" in state
        assert "error" in state["kwargs"]
        assert re.search(err_match, state["kwargs"]["error"]) is not None
    else:
        body, status = blueprints.guts.handle_500(exc)
        assert status == 500
        body_json = json.loads(body)
        assert "error" in body_json
        assert re.search(err_match, body_json["error"]) is not None


@pytest.mark.parametrize(
    (
        "session_user",
        "header_user",
        "arg_user",
        "authd",
        "user_response",
        "userinfo_response",
        "expected_user",
    ),
    [
        pytest.param(
            "session-pytest",
            None,
            None,
            True,
            {"login": "session-pytest"},
            {"email": "session-pytest"},
            "session-pytest",
            id="happy_session",
        ),
        pytest.param(
            None,
            "header-pytest",
            None,
            True,
            {"login": "header-pytest"},
            {"email": "header-pytest"},
            "header-pytest",
            id="happy_header",
        ),
        pytest.param(
            None,
            None,
            "arg-pytest",
            True,
            {"login": "arg-pytest"},
            {"email": "arg-pytest"},
            "arg-pytest",
            id="happy_arg",
        ),
        pytest.param(
            None,
            None,
            None,
            False,
            {},
            {},
            None,
            id="happy_nothing",
        ),
        pytest.param(
            "session-pytest",
            "session-pytest",
            "session-pytest",
            False,
            {},
            {},
            None,
            id="expired_token",
        ),
        pytest.param(
            "elmer",
            None,
            None,
            False,
            {"login": "bugs"},
            {"email": "bugs"},
            None,
            id="mismatched",
        ),
    ],
)
def test_set_user(
    monkeypatch,
    fake_oauth_session,
    session_user,
    header_user,
    arg_user,
    authd,
    user_response,
    userinfo_response,
    expected_user,
    app,
):
    fake_oauth_session.responses["/user"] = user_response
    fake_oauth_session.responses["userinfo"] = userinfo_response
    fake_oauth_session.authorized = authd
    fake_oauth_session.token = "unchanged"

    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)
    monkeypatch.setattr(app.config["oauth_blueprint"], "session", fake_oauth_session)

    def fake_is_fully_authd():
        return authd

    monkeypatch.setattr(auth, "is_fully_authd", fake_is_fully_authd)

    fake_session = {"user": session_user}

    monkeypatch.setattr(flask, "session", fake_session)
    monkeypatch.setattr(
        flask,
        "request",
        conftest.FakeRequest({"Fuzzbucket-User": header_user}, {"user": arg_user}, {}),
    )

    with app.test_client() as c:
        response = c.get("/whoami")
        assert response is not None
        assert response.json is not None
        assert response.json.get("you") == expected_user
