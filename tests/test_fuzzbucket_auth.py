import flask

from fuzzbucket import auth


def test_load_user_from_request(
    app,
    dynamodb,
    fake_oauth_session,
    monkeypatch,
):
    with app.test_request_context("/cranberry/sauce"):
        loaded_user = auth.load_user_from_request(flask.request)
        assert loaded_user is None

    with app.test_request_context("/pumpkin/pie", headers={"fuzzbucket-user": "crust"}):
        loaded_user = auth.load_user_from_request(flask.request)
        assert loaded_user is not None
        assert loaded_user.user_id == "crust"
        assert not loaded_user.is_authenticated

    with app.test_request_context(
        "/marshmallow/soup", query_string={"user": "charizard"}
    ):
        loaded_user = auth.load_user_from_request(flask.request)
        assert loaded_user is not None
        assert loaded_user.user_id == "charizard"
        assert not loaded_user.is_authenticated

    with monkeypatch.context() as mp:
        mp.setattr(flask, "session", {"user": "rumples"})

        with app.test_request_context("/yam/salad"):
            loaded_user = auth.load_user_from_request(flask.request)
            assert loaded_user is not None
            assert loaded_user.user_id == "rumples"
            assert not loaded_user.is_authenticated
