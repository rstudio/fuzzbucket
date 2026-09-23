import typing

import flask
import pytest

import conftest
from fuzzbucket import aws, cfg, user


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
def test_list_boxes(
    app,
    dynamodb,
    ec2,
    fake_users,
    fake_oauth_session,
    authd,
    expected,
):
    fake_oauth_session.authorized = authd

    with app.test_client(user=(user.User.load("pytest") if authd else None)) as c:
        response = c.get(
            "/box/",
            headers={
                "fuzzbucket-user": "pytest",
                "fuzzbucket-secret": fake_users.get("pytest", ""),
            },
        )
        assert response is not None
        assert response.status_code == expected

        if not authd:
            return

        assert response.json is not None
        assert "boxes" in response.json
        assert response.json["boxes"] is not None


@pytest.mark.parametrize(
    ("authd", "payload", "expected"),
    [
        pytest.param(
            True,
            dict(ami="ami-fafafafafaf"),
            201,
            id="happy",
        ),
        pytest.param(False, dict(ami="ami-fafafafafaf"), 403, id="forbidden"),
        pytest.param(True, dict(ami="ami-ohno"), 400, id="bogus_ami"),
        pytest.param(
            True,
            dict(ami="ami-fafafafafaf", root_volume_size=11),
            201,
            id="with_root_volume_size",
        ),
        pytest.param(
            True,
            dict(ami="ami-fafafafafaf", instance_tags={"fb:environment": "production"}),
            201,
            id="with_instance_tags",
        ),
    ],
)
def test_create_box(
    app,
    dynamodb,
    ec2,
    fake_users,
    fake_oauth_session,
    monkeypatch,
    pubkey,
    authd,
    payload,
    expected,
):
    fake_oauth_session.responses["/user"]["login"] = "lordtestingham"
    fake_oauth_session.authorized = authd

    if cfg.AUTH_PROVIDER == "oauth":

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

    def fake_describe_images(ImageIds=(), *_, **__):
        return {
            "ami-fafafafafaf": {
                "Images": [
                    {
                        "RootDeviceName": "/dev/xyz",
                        "BlockDeviceMappings": [
                            {
                                "DeviceName": "/dev/xyz",
                                "Ebs": {"VolumeSize": 9},
                            }
                        ],
                    }
                ]
            },
        }.get(ImageIds[0], {"Images": []})

    monkeypatch.setattr(ec2, "describe_images", fake_describe_images)

    response = None
    with monkeypatch.context() as mp:
        mp.setattr(aws, "fetch_first_compatible_github_key", lambda _: pubkey)
        with app.test_client(
            user=(user.User.load("lordtestingham") if authd else None)
        ) as c:
            response = c.post(
                "/box/",
                json=payload,
                headers={
                    "fuzzbucket-user": "lordtestingham",
                    "fuzzbucket-secret": fake_users.get("lordtestingham", ""),
                },
            )

    assert response is not None
    assert response.status_code == expected

    if authd and expected < 300:
        assert response.json is not None
        assert "boxes" in response.json
        assert response.json["boxes"] != []


@pytest.mark.parametrize(
    ("authd", "update_body", "expected"),
    [
        pytest.param(
            True,
            {
                "instance_tags": {"withered": "hand", "early": "seasons"},
                "ttl": "108000.0",
            },
            200,
            id="happy",
        ),
        pytest.param(
            True,
            {
                "ttl": "108000.0",
            },
            200,
            id="happy_ttl_only",
        ),
        pytest.param(
            True,
            {
                "instance_tags": {"withered": "hand", "early": "seasons"},
            },
            200,
            id="happy_tags_only",
        ),
        pytest.param(False, {}, 403, id="forbidden"),
    ],
)
def test_update_box(
    app,
    dynamodb,
    ec2,
    fake_users,
    fake_oauth_session,
    monkeypatch,
    pubkey,
    authd,
    update_body,
    expected,
):
    def fake_describe_key_pairs():
        return {
            "KeyPairs": [
                {
                    "KeyName": "pytest",
                    "KeyPairId": "key-fafafafafafafafaf",
                    "KeyFingerprint": "ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa",
                }
            ]
        }

    monkeypatch.setattr(ec2, "describe_key_pairs", fake_describe_key_pairs)

    def fake_describe_images(*_, **__):
        return {
            "Images": [
                {
                    "RootDeviceName": "/dev/xyz",
                    "BlockDeviceMappings": [
                        {"DeviceName": "/dev/xyz", "Ebs": {"VolumeSize": 9}}
                    ],
                }
            ]
        }

    monkeypatch.setattr(ec2, "describe_images", fake_describe_images)

    boxes: list[conftest.AnyDict]

    with monkeypatch.context() as mp:
        mp.setattr(aws, "fetch_first_compatible_github_key", lambda _: pubkey)
        with app.test_client(user=user.User.load("pytest")) as c:
            response = c.post(
                "/box/",
                json={"ami": "ami-fafafafafaf"},
                headers={
                    "fuzzbucket-user": "pytest",
                    "fuzzbucket-secret": fake_users.get("pytest", ""),
                },
            )
            assert response.status_code == 201

            boxes = response.json.get("boxes", [])

    assert boxes is not None
    assert len(boxes) > 0

    fake_oauth_session.authorized = authd

    with app.test_client(user=(user.User.load("pytest") if authd else None)) as c:
        with monkeypatch.context() as mp:
            all_instances = ec2.describe_instances()

            def fake_describe_instances(*_, **__):
                return all_instances

            mp.setattr(
                ec2,
                "describe_instances",
                fake_describe_instances,
            )

            response = c.put(
                f'/box/{boxes[0]["instance_id"]}',
                json=update_body,
                headers={
                    "fuzzbucket-user": "pytest",
                    "fuzzbucket-secret": fake_users.get("pytest", ""),
                },
            )

            assert response.status_code == expected

    if "ttl" in update_body:
        re_fetched = aws.list_boxes_filtered(ec2, [])
        assert re_fetched[0].ttl == int(float(update_body["ttl"]))


@pytest.mark.parametrize(
    ("authd", "expected"),
    [
        pytest.param(
            True,
            204,
            id="happy",
        ),
        pytest.param(False, 403, id="forbidden"),
    ],
)
def test_delete_box(
    app,
    dynamodb,
    ec2,
    fake_users,
    fake_oauth_session,
    monkeypatch,
    pubkey,
    authd,
    expected,
):
    def fake_describe_key_pairs():
        return {
            "KeyPairs": [
                {
                    "KeyName": "pytest",
                    "KeyPairId": "key-fafafafafafafafaf",
                    "KeyFingerprint": "ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa",
                }
            ]
        }

    monkeypatch.setattr(ec2, "describe_key_pairs", fake_describe_key_pairs)

    def fake_describe_images(*_, **__):
        return {
            "Images": [
                {
                    "RootDeviceName": "/dev/xyz",
                    "BlockDeviceMappings": [
                        {"DeviceName": "/dev/xyz", "Ebs": {"VolumeSize": 9}}
                    ],
                }
            ]
        }

    monkeypatch.setattr(ec2, "describe_images", fake_describe_images)

    response = None
    with monkeypatch.context() as mp:
        mp.setattr(aws, "fetch_first_compatible_github_key", lambda _: pubkey)
        with app.test_client(user=(user.User.load("pytest") if authd else None)) as c:
            response = c.post(
                "/box/",
                json={"ami": "ami-fafafafafaf"},
                headers={
                    "fuzzbucket-user": "pytest",
                    "fuzzbucket-secret": fake_users.get("pytest", ""),
                },
            )

    assert response is not None
    assert "boxes" in typing.cast(conftest.AnyDict, response.json)

    fake_oauth_session.authorized = authd

    with app.test_client(user=(user.User.load("pytest") if authd else None)) as c:
        all_instances = ec2.describe_instances()

        def fake_describe_instances(*_, **__):
            return all_instances

        monkeypatch.setattr(
            ec2,
            "describe_instances",
            fake_describe_instances,
        )
        response = c.delete(
            f'/box/{typing.cast(conftest.AnyDict, response.json)["boxes"][0]["instance_id"]}',
            headers={
                "fuzzbucket-user": "pytest",
                "fuzzbucket-secret": fake_users.get("pytest", ""),
            },
        )
        assert response.status_code == expected


def test_delete_box_not_yours(
    app,
    dynamodb,
    monkeypatch,
    fake_users,
    fake_oauth_session,
):
    def fake_list_user_boxes(*_):
        return []

    monkeypatch.setattr(aws, "list_user_boxes", fake_list_user_boxes)

    response = None

    with app.test_client(user=user.User.load("pytest")) as c:
        response = c.delete(
            "/box/i-fafababacaca",
            headers={
                "fuzzbucket-user": "pytest",
                "fuzzbucket-secret": fake_users.get("pytest", ""),
            },
        )

    assert response is not None
    assert response.status_code == 403
    assert "error" in typing.cast(conftest.AnyDict, response.json)
    assert typing.cast(conftest.AnyDict, response.json)["error"] == "no touching"


@pytest.mark.parametrize(
    ("authd", "expected"),
    [
        pytest.param(
            True,
            204,
            id="happy",
        ),
        pytest.param(False, 403, id="forbidden"),
    ],
)
def test_reboot_box(
    app,
    dynamodb,
    ec2,
    fake_users,
    fake_oauth_session,
    monkeypatch,
    pubkey,
    authd,
    expected,
):
    def fake_describe_key_pairs():
        return {
            "KeyPairs": [
                {
                    "KeyName": "pytest",
                    "KeyPairId": "key-fafafafafafafafaf",
                    "KeyFingerprint": "ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa",
                }
            ]
        }

    monkeypatch.setattr(ec2, "describe_key_pairs", fake_describe_key_pairs)

    def fake_describe_images(*_, **__):
        return {
            "Images": [
                {
                    "RootDeviceName": "/dev/xyz",
                    "BlockDeviceMappings": [
                        {"DeviceName": "/dev/xyz", "Ebs": {"VolumeSize": 9}}
                    ],
                }
            ]
        }

    monkeypatch.setattr(ec2, "describe_images", fake_describe_images)

    boxes: list[conftest.AnyDict]

    with monkeypatch.context() as mp:
        mp.setattr(aws, "fetch_first_compatible_github_key", lambda _: pubkey)
        with app.test_client(user=(user.User.load("pytest") if authd else None)) as c:
            response = c.post(
                "/box/",
                json={"ami": "ami-fafafafafaf"},
                headers={
                    "fuzzbucket-user": "pytest",
                    "fuzzbucket-secret": fake_users.get("pytest", ""),
                },
            )

            assert response.status_code == 201

            boxes = response.json.get("boxes", [])

    assert boxes is not None
    assert len(boxes) > 0

    fake_oauth_session.authorized = authd

    with app.test_client(user=(user.User.load("pytest") if authd else None)) as c:
        all_instances = ec2.describe_instances()
        with monkeypatch.context() as mp:

            def fake_describe_instances(*_, **__):
                return all_instances

            mp.setattr(
                ec2,
                "describe_instances",
                fake_describe_instances,
            )
            instance_id = boxes[0]["instance_id"]
            response = c.post(
                f"/box/{instance_id}/reboot",
                headers={
                    "fuzzbucket-user": "pytest",
                    "fuzzbucket-secret": fake_users.get("pytest", ""),
                },
            )
            assert response.status_code == expected


def test_reboot_box_not_yours(
    app,
    dynamodb,
    ec2,
    fake_users,
    fake_oauth_session,
    monkeypatch,
):
    def fake_list_user_boxes(*_):
        return []

    monkeypatch.setattr(aws, "list_user_boxes", fake_list_user_boxes)

    with app.test_client(user=user.User.load("pytest")) as c:
        response = c.post(
            "/box/i-fafafafaf/reboot",
            headers={
                "fuzzbucket-user": "pytest",
                "fuzzbucket-secret": fake_users.get("pytest", ""),
            },
        )
        assert response is not None
        assert response.status_code == 403
        assert "error" in typing.cast(conftest.AnyDict, response.json)
        assert typing.cast(conftest.AnyDict, response.json)["error"] == "no touching"


def test_create_box_root_volume_is_gp3(
    app,
    dynamodb,
    ec2,
    fake_users,
    fake_oauth_session,
    monkeypatch,
    pubkey,
):
    """The AMI's own mapping carries no VolumeType (gp2 by AWS default);
    the box must still be launched on gp3."""
    fake_oauth_session.responses["/user"]["login"] = "lordtestingham"
    fake_oauth_session.authorized = True

    if cfg.AUTH_PROVIDER == "oauth":
        monkeypatch.setattr(
            ec2,
            "describe_key_pairs",
            lambda: {
                "KeyPairs": [
                    {
                        "KeyName": "lordTestingham",
                        "KeyPairId": "key-fafafafafafafafaf",
                        "KeyFingerprint": "ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa",
                    }
                ]
            },
        )

    monkeypatch.setattr(
        ec2,
        "describe_images",
        lambda ImageIds=(), *_, **__: {
            "Images": [
                {
                    "RootDeviceName": "/dev/xyz",
                    "BlockDeviceMappings": [
                        {"DeviceName": "/dev/xyz", "Ebs": {"VolumeSize": 9}}
                    ],
                }
            ]
        },
    )

    seen: dict[str, typing.Any] = {}
    real_run_instances = ec2.run_instances

    def spy_run_instances(**kwargs):
        seen.update(kwargs)
        return real_run_instances(**kwargs)

    monkeypatch.setattr(ec2, "run_instances", spy_run_instances)

    with monkeypatch.context() as mp:
        mp.setattr(aws, "fetch_first_compatible_github_key", lambda _: pubkey)
        with app.test_client(user=user.User.load("lordtestingham")) as c:
            response = c.post(
                "/box/",
                json=dict(ami="ami-fafafafafaf", root_volume_size=11),
                headers={
                    "fuzzbucket-user": "lordtestingham",
                    "fuzzbucket-secret": fake_users.get("lordtestingham", ""),
                },
            )

    # The launch request is what matters here; the response path is covered
    # by test_create_box.
    assert "BlockDeviceMappings" in seen, response.status_code
    ebs = seen["BlockDeviceMappings"][0]["Ebs"]
    assert ebs["VolumeType"] == "gp3"
    assert ebs["VolumeSize"] == 11
