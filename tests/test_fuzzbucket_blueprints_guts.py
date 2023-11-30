import json
import re

import flask
import pytest
import werkzeug.exceptions

import conftest
from fuzzbucket import blueprints, user


def test_login(app, dynamodb, fake_users, fake_oauth_session):
    fake_oauth_session.authorized = False

    with app.test_client() as c:
        response = c.get(
            "/_login?user=pytest",
            headers={
                "fuzzbucket-user": "pytest",
                "fuzzbucket-secret": fake_users.get("pytest", ""),
            },
        )

        assert response is not None
        assert response.status_code == 302
        assert "location" in response.headers
        assert response.headers["location"].startswith("/login/")


@pytest.mark.parametrize(
    ("authd", "session_user", "expected_status"),
    [
        pytest.param(True, "pytest", 204, id="happy"),
        pytest.param(False, "pytest", 403, id="not_logged_in"),
        pytest.param(True, "eggs", 403, id="unknown_user"),
    ],
)
def test_logout(
    app,
    dynamodb,
    fake_users,
    authd,
    session_user,
    expected_status,
    fake_oauth_session,
):
    fake_oauth_session.authorized = authd
    fake_oauth_session.responses["/user"]["login"] = session_user

    with app.test_client(user=(user.User.load(session_user) if authd else None)) as c:
        response = c.post(
            "/_logout",
            headers={
                "fuzzbucket-user": session_user,
                "fuzzbucket-secret": fake_users.get(session_user, ""),
            },
        )

        assert response is not None
        assert response.status_code == expected_status


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
