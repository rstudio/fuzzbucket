import typing

import flask
import pytest

from fuzzbucket import cfg, user


class TemplateResponse(typing.NamedTuple):
    template_name: str
    status_code: int


@pytest.mark.parametrize(
    ("allowed_orgs", "orgs_response", "expected"),
    (
        [
            pytest.param(
                {"frobs", "globs"},
                [{"login": "frobs"}],
                TemplateResponse("auth_complete.html", 200),
                id="happy",
            ),
            pytest.param(
                {"frobs", "globs"},
                [],
                TemplateResponse("error.html", 403),
                id="forbidden",
            ),
            pytest.param(
                {"frobs", "globs"},
                {"message": "now you have gone and also done it"},
                TemplateResponse("error.html", 503),
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
    state = {}

    def fake_render_template(template_name, **kwargs):
        state.update(template_name=template_name, kwargs=kwargs)
        return "RENDERED"

    monkeypatch.setattr(flask, "render_template", fake_render_template)
    monkeypatch.setattr(flask, "session", {"user": "pytest"})

    fake_oauth_session.responses["/user/orgs"] = orgs_response

    monkeypatch.setattr(cfg, "ALLOWED_GITHUB_ORGS", allowed_orgs)

    with app.test_client(user=user.User.load("pytest")) as c:
        response = c.get("/login/auth-complete")

        assert response is not None
        assert response.status_code == expected.status_code
        assert state["template_name"] == expected.template_name
