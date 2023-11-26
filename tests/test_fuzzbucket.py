import typing

import fuzzbucket
from fuzzbucket import auth, blueprints, reaper


def test_deferred_app(fake_oauth_session, monkeypatch):
    fake_oauth_session.authorized = False
    monkeypatch.setattr(auth, "github", fake_oauth_session)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    state = {}

    def fake_start_response(status, headers):
        state.update(status=status, headers=headers)

    response = fuzzbucket.deferred_app(
        {
            "BUSTED_ENV": typing.cast(str, True),
            "REQUEST_METHOD": "BORK",
            "SERVER_NAME": "nope.example.com",
            "SERVER_PORT": "64434",
            "wsgi.url_scheme": "http",
        },
        fake_start_response,
    )
    assert response is not None
    assert state["status"][0] == "4"
    assert dict(state["headers"])["Content-Length"] > "0"


def test_deferred_reap_boxes(monkeypatch):
    state = {}

    def fake_reap_boxes(event, context):
        state.update(event=event, context=context)

    monkeypatch.setattr(reaper, "reap_boxes", fake_reap_boxes)
    fuzzbucket.deferred_reap_boxes({"oh": "hai"}, {"pro": "image"})
    assert state["event"] == {"oh": "hai"}
    assert state["context"] == {"pro": "image"}
