import typing

import boto3
import flask
import moto
import pytest

import conftest
from fuzzbucket import auth, aws, blueprints, cfg


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
@moto.mock_ec2
@moto.mock_dynamodb
def test_list_boxes(
    app, authd_headers, fake_oauth_session, monkeypatch, authd, expected
):
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(aws, "get_ec2_client", lambda: boto3.client("ec2"))
    monkeypatch.setattr(auth, "is_fully_authd", lambda: authd)
    fake_oauth_session.authorized = authd
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    with app.test_client() as c:
        response = c.get("/box/", headers=authd_headers)
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
@moto.mock_ec2
@moto.mock_dynamodb
def test_create_box(
    app,
    authd_headers,
    fake_oauth_session,
    monkeypatch,
    pubkey,
    authd,
    payload,
    expected,
):
    ec2_client = boto3.client("ec2")
    monkeypatch.setattr(aws, "get_ec2_client", lambda: ec2_client)
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: authd)
    fake_oauth_session.authorized = authd
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    if cfg.AUTH_PROVIDER == "oauth":
        monkeypatch.setattr(flask, "session", {"user": "lordtestingham"})

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

        monkeypatch.setattr(ec2_client, "describe_key_pairs", fake_describe_key_pairs)

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

    monkeypatch.setattr(ec2_client, "describe_images", fake_describe_images)

    response = None
    with monkeypatch.context() as mp:
        mp.setattr(aws, "fetch_first_compatible_github_key", lambda _: pubkey)
        with app.test_client() as c:
            response = c.post(
                "/box/",
                json=payload,
                headers=authd_headers,
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
@moto.mock_ec2
@moto.mock_dynamodb
def test_update_box(
    app,
    authd_headers,
    fake_oauth_session,
    monkeypatch,
    pubkey,
    authd,
    update_body,
    expected,
):
    ec2_client = boto3.client("ec2")
    monkeypatch.setattr(aws, "get_ec2_client", lambda: ec2_client)
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: True)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

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

    monkeypatch.setattr(ec2_client, "describe_key_pairs", fake_describe_key_pairs)

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

    monkeypatch.setattr(ec2_client, "describe_images", fake_describe_images)

    response = None
    with monkeypatch.context() as mp:
        mp.setattr(aws, "fetch_first_compatible_github_key", lambda _: pubkey)
        with app.test_client() as c:
            response = c.post(
                "/box/", json={"ami": "ami-fafafafafaf"}, headers=authd_headers
            )
    assert response is not None
    assert "boxes" in typing.cast(conftest.AnyDict, response.json)

    with app.test_client() as c:
        with monkeypatch.context() as mp:
            all_instances = ec2_client.describe_instances()

            def fake_describe_instances(*_, **__):
                return all_instances

            mp.setattr(
                ec2_client,
                "describe_instances",
                fake_describe_instances,
            )
            mp.setattr(auth, "is_fully_authd", lambda: authd)
            response = c.put(
                f'/box/{typing.cast(conftest.AnyDict, response.json)["boxes"][0]["instance_id"]}',
                json=update_body,
                headers=authd_headers,
            )
            assert response.status_code == expected

    if "ttl" in update_body:
        re_fetched = aws.list_boxes_filtered(ec2_client, [])
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
@moto.mock_ec2
@moto.mock_dynamodb
def test_delete_box(
    app, authd_headers, fake_oauth_session, monkeypatch, pubkey, authd, expected
):
    ec2_client = boto3.client("ec2")
    monkeypatch.setattr(aws, "get_ec2_client", lambda: ec2_client)
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: True)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

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

    monkeypatch.setattr(ec2_client, "describe_key_pairs", fake_describe_key_pairs)

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

    monkeypatch.setattr(ec2_client, "describe_images", fake_describe_images)

    response = None
    with monkeypatch.context() as mp:
        mp.setattr(aws, "fetch_first_compatible_github_key", lambda _: pubkey)
        with app.test_client() as c:
            response = c.post(
                "/box/", json={"ami": "ami-fafafafafaf"}, headers=authd_headers
            )

    assert response is not None
    assert "boxes" in typing.cast(conftest.AnyDict, response.json)

    with app.test_client() as c:
        all_instances = ec2_client.describe_instances()

        def fake_describe_instances(*_, **__):
            return all_instances

        monkeypatch.setattr(
            ec2_client,
            "describe_instances",
            fake_describe_instances,
        )
        monkeypatch.setattr(auth, "is_fully_authd", lambda: authd)
        response = c.delete(
            f'/box/{typing.cast(conftest.AnyDict, response.json)["boxes"][0]["instance_id"]}',
            headers=authd_headers,
        )
        assert response.status_code == expected


@moto.mock_ec2
@moto.mock_dynamodb
def test_delete_box_not_yours(app, monkeypatch, authd_headers, fake_oauth_session):
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)

    def fake_list_user_boxes(*_):
        return []

    monkeypatch.setattr(aws, "list_user_boxes", fake_list_user_boxes)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: True)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    response = None

    with app.test_client() as c:
        response = c.delete("/box/i-fafababacaca", headers=authd_headers)

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
@moto.mock_ec2
@moto.mock_dynamodb
def test_reboot_box(
    app, authd_headers, fake_oauth_session, monkeypatch, pubkey, authd, expected
):
    ec2_client = boto3.client("ec2")
    monkeypatch.setattr(aws, "get_ec2_client", lambda: ec2_client)
    dynamodb = boto3.resource("dynamodb")
    conftest.setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: True)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

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

    monkeypatch.setattr(ec2_client, "describe_key_pairs", fake_describe_key_pairs)

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

    monkeypatch.setattr(ec2_client, "describe_images", fake_describe_images)

    response = None
    with monkeypatch.context() as mp:
        mp.setattr(aws, "fetch_first_compatible_github_key", lambda _: pubkey)
        with app.test_client() as c:
            response = c.post(
                "/box/", json={"ami": "ami-fafafafafaf"}, headers=authd_headers
            )

    assert response is not None
    assert "boxes" in typing.cast(conftest.AnyDict, response.json)

    with app.test_client() as c:
        all_instances = ec2_client.describe_instances()
        with monkeypatch.context() as mp:

            def fake_describe_instances(*_, **__):
                return all_instances

            mp.setattr(
                ec2_client,
                "describe_instances",
                fake_describe_instances,
            )
            mp.setattr(auth, "is_fully_authd", lambda: authd)
            instance_id = typing.cast(conftest.AnyDict, response.json)["boxes"][0][
                "instance_id"
            ]
            response = c.post(
                f"/box/{instance_id}/reboot",
                headers=authd_headers,
            )
            assert response.status_code == expected


@moto.mock_ec2
def test_reboot_box_not_yours(app, fake_oauth_session, monkeypatch):
    def fake_list_user_boxes(*_):
        return []

    monkeypatch.setattr(aws, "list_user_boxes", fake_list_user_boxes)
    monkeypatch.setattr(auth, "is_fully_authd", lambda: True)
    monkeypatch.setattr(auth, "github", fake_oauth_session)
    monkeypatch.setattr(blueprints.guts, "github", fake_oauth_session)

    with app.test_client() as c:
        response = c.post("/box/i-fafafafaf/reboot")
        assert response is not None
        assert response.status_code == 403
        assert "error" in typing.cast(conftest.AnyDict, response.json)
        assert typing.cast(conftest.AnyDict, response.json)["error"] == "no touching"
