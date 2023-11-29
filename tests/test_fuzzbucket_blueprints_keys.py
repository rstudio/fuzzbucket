import pytest

from fuzzbucket import aws, user


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
            "nerf",
            "chuckit",
            404,
            id="missing",
        ),
        pytest.param(False, "foible", "default", 403, id="forbidden"),
    ],
)
def test_get_key(
    app,
    dynamodb,
    ec2,
    fake_oauth_session,
    fake_users,
    monkeypatch,
    authd,
    session_user,
    key_alias,
    expected,
):
    fake_oauth_session.authorized = authd
    fake_oauth_session.responses["/user"]["login"] = session_user

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

    monkeypatch.setattr(ec2, "describe_key_pairs", fake_describe_key_pairs)

    with app.test_client(user=(user.User.load(session_user) if authd else None)) as c:
        response = c.get(
            f"/key/{key_alias}",
            headers={
                "fuzzbucket-user": session_user,
                "fuzzbucket-secret": fake_users.get(session_user, ""),
            },
        )

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
def test_list_keys(
    app,
    dynamodb,
    ec2,
    fake_oauth_session,
    fake_users,
    monkeypatch,
    authd,
    session_user,
    n_keys,
    expected,
):
    fake_oauth_session.authorized = authd
    fake_oauth_session.responses["/user"]["login"] = session_user

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

    monkeypatch.setattr(ec2, "describe_key_pairs", fake_describe_key_pairs)

    with app.test_client(user=(user.User.load(session_user) if authd else None)) as c:
        response = c.get(
            "/key/",
            headers={
                "fuzzbucket-user": session_user,
                "fuzzbucket-secret": fake_users.get(session_user, ""),
            },
        )
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
def test_put_key(
    app,
    dynamodb,
    ec2,
    fake_oauth_session,
    fake_users,
    monkeypatch,
    authd,
    session_user,
    key_alias,
    request_kwargs,
    expected,
):
    fake_oauth_session.authorized = authd
    fake_oauth_session.responses["/user"]["login"] = session_user

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

    monkeypatch.setattr(ec2, "describe_key_pairs", fake_describe_key_pairs)

    response = None

    with app.test_client(user=(user.User.load(session_user) if authd else None)) as c:
        response = c.put(
            f"/key/{key_alias}",
            headers={
                "fuzzbucket-user": session_user,
                "fuzzbucket-secret": fake_users.get(session_user, ""),
            },
            **request_kwargs,
        )

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
def test_delete_key(
    app,
    dynamodb,
    ec2,
    fake_oauth_session,
    fake_users,
    monkeypatch,
    authd,
    session_user,
    key_alias,
    expected,
):
    fake_oauth_session.authorized = authd
    fake_oauth_session.responses["/user"]["login"] = session_user

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

    monkeypatch.setattr(ec2, "describe_key_pairs", fake_describe_key_pairs)

    with app.test_client(user=(user.User.load(session_user) if authd else None)) as c:
        response = c.delete(
            f"/key/{key_alias}",
            headers={
                "fuzzbucket-user": session_user,
                "fuzzbucket-secret": fake_users.get(session_user, ""),
            },
        )

        assert response is not None
        assert response.status_code == expected

        if authd and expected < 400:
            assert response.json is not None
            assert "key" in response.json
            assert response.json["key"] is not None
