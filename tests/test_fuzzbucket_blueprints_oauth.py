import flask
import flask_dance.contrib.github
import pytest

import conftest
from fuzzbucket import aws, cfg, user


@pytest.mark.parametrize(
    ("allowed_orgs", "orgs_response", "expected"),
    (
        [
            pytest.param(
                {"frobs", "globs"},
                [{"login": "frobs"}],
                conftest.TemplateResponse("auth_complete.html", 200),
                id="happy",
            ),
            pytest.param(
                {"frobs", "globs"},
                [],
                conftest.TemplateResponse("error.html", 403),
                id="forbidden",
            ),
            pytest.param(
                {"frobs", "globs"},
                {"message": "now you have gone and also done it"},
                conftest.TemplateResponse("error.html", 503),
                id="github_err",
            ),
        ]
        if cfg.AUTH_PROVIDER == "github-oauth"
        else []
    ),
)
def test_auth_complete(
    app,
    dynamodb,
    monkeypatch,
    fake_oauth_session,
    allowed_orgs,
    orgs_response,
    expected,
):
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)

    state = {}

    def fake_render_template(template_name, **kwargs):
        state.update(template_name=template_name, kwargs=kwargs)
        return "RENDERED"

    monkeypatch.setattr(flask, "render_template", fake_render_template)
    monkeypatch.setattr(flask, "session", {"user": "pytest"})

    fake_oauth_session.responses["/user/orgs"] = orgs_response
    monkeypatch.setattr(user, "github", fake_oauth_session)
    monkeypatch.setattr(flask_dance.contrib.github, "github", fake_oauth_session)

    monkeypatch.setattr(cfg, "ALLOWED_GITHUB_ORGS", allowed_orgs)

    with app.test_client(user=user.User.load("pytest")) as c:
        response = c.get("/login/auth-complete")

        assert response is not None
        assert response.status_code == expected.status_code
        assert state["template_name"] == expected.template_name
