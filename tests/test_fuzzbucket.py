import base64
import contextlib
import json
import os
import random
import time
import typing
import urllib.request

import boto3
import botocore.exceptions
import pytest

from moto import mock_ec2, mock_dynamodb2

import fuzzbucket
import fuzzbucket.app
import fuzzbucket.reaper

from fuzzbucket.app import app
from fuzzbucket.box import Box


@pytest.fixture(autouse=True)
def env_setup():
    os.environ.setdefault("CF_VPC", "vpc-fafafafaf")
    os.environ.setdefault("FUZZBUCKET_IMAGE_ALIASES_TABLE_NAME", "image-aliases")
    app.testing = True


@pytest.fixture
def authd_headers() -> typing.List[typing.Tuple[str, str]]:
    return [("Authorization", base64.b64encode(b"pytest:zzz").decode("utf-8"))]


@pytest.fixture
def pubkey() -> str:
    return "".join(
        [
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcKKyTEzdI6zFMEmhbXSLemjTskw620yumv",
            "bhoGwrY4zun/1cz+obxk1DZ+j0AfVTA9EQCr7AsFX3KRrevEBgHvWcK3vDp2h2pz/naM40SwF",
            "dLK1+2G8vFy6zWZlFvQSNj8D6pxKGb6e0I3oVRBPd1V8z0AIswe2/9BiDi1K3Mx4yDoidZwnU",
            "qweCCWwv3Y6nHkveEtVZlm8btGrlo2ya4IdCV2/KUK7FDbhGkLS7ZidVi+hS2GcrOTZYAkQW5",
            "aS6r/QYTQGz94RjmyOFam5GhW5zboFdYnF9QD4WUGr4Gn9iI6QxaV50UXv37v+6pCaNYMPUjI",
            f"SFQFMNhHnnMwcnx pytest@nowhere{random.randint(100, 999)}",
        ]
    )


def setup_dynamodb_tables(dynamodb):
    table_name = os.getenv("FUZZBUCKET_IMAGE_ALIASES_TABLE_NAME")
    table = dynamodb.create_table(
        AttributeDefinitions=[dict(AttributeName="alias", AttributeType="S")],
        KeySchema=[dict(AttributeName="alias", KeyType="HASH")],
        TableName=table_name,
    )
    table.meta.client.get_waiter("table_exists").wait(TableName=table_name)

    for alias, ami in {
        "ubuntu18": "ami-fafafafafaf",
        "rhel8": "ami-fafafafafaa",
    }.items():
        table.put_item(Item=dict(user="pytest", alias=alias, ami=ami))


def test_deferred_app():
    state = {}

    def fake_start_response(status, headers):
        state.update(status=status, headers=headers)

    response = fuzzbucket.deferred_app(
        {"BUSTED_ENV": True, "REQUEST_METHOD": "BORK"}, fake_start_response
    )
    assert response is not None
    assert state["status"] == "403 FORBIDDEN"
    assert dict(state["headers"])["Content-Length"] > "0"


def test_deferred_reap_boxes(monkeypatch):
    state = {}

    def fake_reap_boxes(event, context):
        state.update(event=event, context=context)

    monkeypatch.setattr(fuzzbucket.reaper, "reap_boxes", fake_reap_boxes)
    fuzzbucket.deferred_reap_boxes({"oh": "hai"}, {"pro": "image"})
    assert state["event"] == {"oh": "hai"}
    assert state["context"] == {"pro": "image"}


def test_get_ec2_client(monkeypatch):
    state = {}

    def fake_client(name):
        state.update(name=name)
        return "client"

    monkeypatch.setattr(boto3, "client", fake_client)
    client = fuzzbucket.get_ec2_client()
    assert state["name"] == "ec2"
    assert client == "client"


@pytest.mark.parametrize("offline", [True, False], ids=["offline", "online"])
def test_get_dynamodb(monkeypatch, offline):
    state = {}

    def fake_resource(name, **kwargs):
        state.update(name=name, kwargs=kwargs)
        return "resource"

    monkeypatch.setattr(boto3, "resource", fake_resource)
    if offline:
        monkeypatch.setenv("IS_OFFLINE", "yep")
    elif "IS_OFFLINE" in os.environ:
        monkeypatch.delenv("IS_OFFLINE")

    fuzzbucket.get_dynamodb.cache_clear()
    resource = fuzzbucket.get_dynamodb()
    assert state["name"] == "dynamodb"
    assert resource == "resource"
    if offline:
        assert state["kwargs"]["region_name"] == "localhost"
        assert state["kwargs"]["endpoint_url"] == "http://localhost:8000"


def test_json_encoder():
    class WithAsJson:
        def as_json(self):
            return {"golden": "feelings"}

    class Dictish:
        def __init__(self):
            self.mellow = "gold"

    other = ("odelay", ["mut", "ati", "ons"])

    def enc(thing):
        return json.dumps(thing, cls=fuzzbucket.app._JSONEncoder)

    assert enc(WithAsJson()) == '{"golden": "feelings"}'
    assert enc(Dictish()) == '{"mellow": "gold"}'
    assert enc(other) == '["odelay", ["mut", "ati", "ons"]]'


@mock_ec2
def test_list_vpc_boxes(monkeypatch):
    state = {}

    def fake_list_boxes_filtered(ec2_client, filters):
        state.update(ec2_client=ec2_client, filters=filters)
        return ["ok"]

    monkeypatch.setattr(fuzzbucket, "list_boxes_filtered", fake_list_boxes_filtered)

    ec2_client = {"ec2_client": "sure"}
    vpc_id = "vpc-fafafafaf"
    listed = fuzzbucket.list_vpc_boxes(ec2_client, vpc_id)
    assert listed == ["ok"]
    assert state["ec2_client"] == ec2_client
    for default_filter in fuzzbucket.DEFAULT_FILTERS:
        assert default_filter in state["filters"]
    assert {"Name": "vpc-id", "Values": [vpc_id]} in state["filters"]


@pytest.mark.parametrize(
    "auth_header,offline,expected_user,expected_status",
    [
        pytest.param(None, False, None, "403 FORBIDDEN", id="forbidden"),
        pytest.param(
            "basic ZmFuY3k6cGFudHM=", False, "fancy", "200 OK", id="basic_authd_user"
        ),
        pytest.param(
            "basic ZmFuY3ktLWRldjpwYW50cw==",
            False,
            "fancy",
            "200 OK",
            id="basic_authd_dev_user",
        ),
        pytest.param(None, True, "offline", "200 OK", id="offline"),
    ],
)
def test_user_middleware(
    monkeypatch, auth_header, offline, expected_user, expected_status
):
    state = {}

    def fake_app(environ, start_response):
        state.update(environ=environ, called=True)
        start_response("200 OK", [])
        return ["ok"]

    def fake_start_response(status, headers):
        state.update(status=status, headers=headers)

    if offline:
        monkeypatch.setenv("IS_OFFLINE", "yep")

    environ = {"HTTP_AUTHORIZATION": auth_header, "REQUEST_METHOD": "BORK"}
    app = fuzzbucket.app._UserMiddleware(fake_app)
    response = app(environ, fake_start_response)
    assert "status" in state
    assert "headers" in state
    if expected_user is not None:
        assert state["environ"]["REMOTE_USER"] == expected_user
    if expected_status is not None:
        assert state["status"] == expected_status
    if expected_status == "200 OK":
        assert state["called"]
        assert response[0] == "ok"


@mock_ec2
def test_list_boxes(authd_headers, monkeypatch):
    monkeypatch.setattr(fuzzbucket.app, "get_ec2_client", lambda: boto3.client("ec2"))
    response = None
    with app.test_client() as c:
        response = c.get("/", headers=authd_headers)
    assert response is not None
    assert response.status_code == 200
    assert response.json is not None
    assert "boxes" in response.json
    assert response.json["boxes"] is not None


@mock_ec2
def test_list_boxes_forbidden(monkeypatch):
    monkeypatch.setattr(fuzzbucket.app, "get_ec2_client", lambda: boto3.client("ec2"))
    response = None
    with app.test_client() as c:
        response = c.get("/")
    assert response.status_code == 403


@mock_ec2
@mock_dynamodb2
def test_create_box(authd_headers, monkeypatch, pubkey):
    monkeypatch.setattr(fuzzbucket.app, "get_ec2_client", lambda: boto3.client("ec2"))
    monkeypatch.setattr(
        fuzzbucket.app, "get_dynamodb", lambda: boto3.resource("dynamodb")
    )
    response = None
    with monkeypatch.context() as mp:
        mp.setattr(fuzzbucket.app, "_fetch_first_github_key", lambda u: pubkey)
        with app.test_client() as c:
            response = c.post(
                "/box", json={"ami": "ami-fafafafafaf"}, headers=authd_headers,
            )
    assert response is not None
    assert response.status_code == 201
    assert response.json is not None
    assert "boxes" in response.json
    assert response.json["boxes"] != []


@mock_ec2
@mock_dynamodb2
def test_create_box_forbidden(monkeypatch):
    monkeypatch.setattr(fuzzbucket.app, "get_ec2_client", lambda: boto3.client("ec2"))
    monkeypatch.setattr(
        fuzzbucket.app, "get_dynamodb", lambda: boto3.resource("dynamodb")
    )
    response = None
    with app.test_client() as c:
        response = c.post("/box", json={"ami": "ami-fafafafafafaf"})
    assert response is not None
    assert response.status_code == 403


@mock_ec2
@mock_dynamodb2
def test_delete_box(authd_headers, monkeypatch, pubkey):
    with app.app_context():
        ec2_client = boto3.client("ec2")
        monkeypatch.setattr(fuzzbucket.app, "get_ec2_client", lambda: ec2_client)
        monkeypatch.setattr(
            fuzzbucket.app, "get_dynamodb", lambda: boto3.resource("dynamodb")
        )
        response = None
        with monkeypatch.context() as mp:
            mp.setattr(fuzzbucket.app, "_fetch_first_github_key", lambda u: pubkey)
            with app.test_client() as c:
                response = c.post(
                    "/box", json={"ami": "ami-fafafafafaf"}, headers=authd_headers
                )
        assert response is not None
        assert "boxes" in response.json

        with app.test_client() as c:
            all_instances = ec2_client.describe_instances()
            with monkeypatch.context() as mp:

                def fake_describe_instances(*_args, **_kwargs):
                    return all_instances

                mp.setattr(
                    ec2_client, "describe_instances", fake_describe_instances,
                )
                response = c.delete(
                    f'/box/{response.json["boxes"][0]["instance_id"]}',
                    headers=authd_headers,
                )
                assert response.status_code == 204


@mock_ec2
def test_delete_box_forbidden(monkeypatch):
    monkeypatch.setattr(fuzzbucket.app, "get_ec2_client", lambda: boto3.client("ec2"))
    response = None
    with app.test_client() as c:
        response = c.delete("/box/i-fafafafaf")
    assert response is not None
    assert response.status_code == 403


@mock_ec2
@mock_dynamodb2
def test_reboot_box(authd_headers, monkeypatch, pubkey):
    with app.app_context():
        ec2_client = boto3.client("ec2")
        monkeypatch.setattr(fuzzbucket.app, "get_ec2_client", lambda: ec2_client)
        monkeypatch.setattr(
            fuzzbucket.app, "get_dynamodb", lambda: boto3.resource("dynamodb")
        )
        response = None
        with monkeypatch.context() as mp:
            mp.setattr(fuzzbucket.app, "_fetch_first_github_key", lambda u: pubkey)
            with app.test_client() as c:
                response = c.post(
                    "/box", json={"ami": "ami-fafafafafaf"}, headers=authd_headers
                )
        assert response is not None
        assert "boxes" in response.json

        with app.test_client() as c:
            all_instances = ec2_client.describe_instances()
            with monkeypatch.context() as mp:

                def fake_describe_instances(*_args, **_kwargs):
                    return all_instances

                mp.setattr(
                    ec2_client, "describe_instances", fake_describe_instances,
                )
                response = c.post(
                    f'/reboot/{response.json["boxes"][0]["instance_id"]}',
                    headers=authd_headers,
                )
                assert response.status_code == 204


@mock_ec2
def test_reboot_box_forbidden(monkeypatch):
    monkeypatch.setattr(fuzzbucket.app, "get_ec2_client", lambda: boto3.client("ec2"))
    response = None
    with app.test_client() as c:
        response = c.post("/reboot/i-fafafafaf")
    assert response is not None
    assert response.status_code == 403


@mock_dynamodb2
def test_list_image_aliases(authd_headers, monkeypatch):
    dynamodb = boto3.resource("dynamodb")
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    setup_dynamodb_tables(dynamodb)
    response = None
    with app.test_client() as c:
        response = c.get("/image-alias", headers=authd_headers)
    assert response is not None
    assert response.status_code == 200


@mock_dynamodb2
def test_list_image_aliases_forbidden(monkeypatch):
    monkeypatch.setattr(
        fuzzbucket.app, "get_dynamodb", lambda: boto3.resource("dynamodb")
    )
    response = None
    with app.test_client() as c:
        response = c.get("/image-alias")
    assert response is not None
    assert response.status_code == 403


@mock_dynamodb2
def test_create_image_alias(authd_headers, monkeypatch):
    dynamodb = boto3.resource("dynamodb")
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    setup_dynamodb_tables(dynamodb)
    response = None
    with app.test_client() as c:
        response = c.post(
            "/image-alias",
            json={"alias": "yikes", "ami": "ami-fafababacaca"},
            headers=authd_headers,
        )
    assert response is not None
    assert response.status_code == 201


@mock_dynamodb2
def test_create_image_alias_not_json(authd_headers, monkeypatch):
    dynamodb = boto3.resource("dynamodb")
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    setup_dynamodb_tables(dynamodb)
    response = None
    with app.test_client() as c:
        response = c.post("/image-alias", data="HAY", headers=authd_headers,)
    assert response is not None
    assert response.status_code == 400


@mock_dynamodb2
def test_delete_image_alias(authd_headers, monkeypatch):
    dynamodb = boto3.resource("dynamodb")
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    setup_dynamodb_tables(dynamodb)
    response = None
    with app.test_client() as c:
        response = c.delete("/image-alias/ubuntu18", headers=authd_headers)
    assert response is not None
    assert response.status_code == 204


@mock_dynamodb2
def test_delete_image_alias_no_alias(authd_headers, monkeypatch):
    dynamodb = boto3.resource("dynamodb")
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    setup_dynamodb_tables(dynamodb)
    response = None
    with app.test_client() as c:
        response = c.delete("/image-alias/nah", headers=authd_headers)
    assert response is not None
    assert response.status_code == 404


@mock_dynamodb2
def test_delete_image_alias_not_yours(monkeypatch):
    dynamodb = boto3.resource("dynamodb")
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    setup_dynamodb_tables(dynamodb)
    response = None
    with app.test_client() as c:
        response = c.delete(
            "/image-alias/ubuntu18",
            headers=[("Authorization", base64.b64encode(b"jag:wagon").decode("utf-8"))],
        )
    assert response is not None
    assert response.status_code == 403


@mock_dynamodb2
@pytest.mark.parametrize(
    "image_alias,raises,expected",
    [
        pytest.param("noice", False, None, id="invalid"),
        pytest.param("rhel8", True, None, id="errored"),
        pytest.param("rhel8", False, "ami-fafafafafaa", id="valid"),
    ],
)
def test_resolve_ami_alias(monkeypatch, image_alias, raises, expected):
    table_name = "just_imagine"
    monkeypatch.setenv("FUZZBUCKET_IMAGE_ALIASES_TABLE_NAME", table_name)

    dynamodb = boto3.resource("dynamodb")
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    setup_dynamodb_tables(dynamodb)

    if raises:

        def boom(*_):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": 1312, "Message": "nah"}}, "wut"
            )

        monkeypatch.setattr(dynamodb, "Table", boom)

    response = fuzzbucket.app._resolve_ami_alias(image_alias)
    assert response == expected


@pytest.mark.parametrize(
    "raises,keys,expected_key",
    [
        pytest.param(False, "first\nsecond\nthird\n", "first", id="3_keys"),
        pytest.param(False, "first", "first", id="1_key"),
        pytest.param(False, "", "", id="empty"),
        pytest.param(True, "first\nsecond\nthird\n", "", id="err_3_keys"),
        pytest.param(True, "first", "", id="err_1_key"),
        pytest.param(True, "", "", id="err_empty"),
    ],
)
def test_fetch_first_github_key(monkeypatch, raises, keys, expected_key):
    class FakeResponse:
        def __init__(self, keys):
            self.keys = keys

        def read(self):
            return self.keys.encode("utf-8")

    @contextlib.contextmanager
    def fake_urlopen(_):
        if raises:
            raise urllib.request.HTTPError("http://nope", 599, "oh no", [], None)
        yield FakeResponse(keys)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert fuzzbucket.app._fetch_first_github_key("user") == expected_key


@mock_ec2
@mock_dynamodb2
def test_reap_boxes(authd_headers, monkeypatch, pubkey):
    monkeypatch.setattr(fuzzbucket.app, "get_ec2_client", lambda: boto3.client("ec2"))
    monkeypatch.setattr(
        fuzzbucket.reaper, "get_ec2_client", lambda: boto3.client("ec2")
    )
    monkeypatch.setattr(
        fuzzbucket.app, "get_dynamodb", lambda: boto3.resource("dynamodb")
    )
    response = None
    with monkeypatch.context() as mp:
        mp.setattr(fuzzbucket.app, "_fetch_first_github_key", lambda u: pubkey)
        with app.test_client() as c:
            response = c.post(
                "/box",
                json={"ttl": "-1", "ami": "ami-fafafafafaf"},
                headers=authd_headers,
            )
    assert response is not None
    assert "boxes" in response.json
    instance_id = response.json["boxes"][0]["instance_id"]
    assert instance_id != ""

    the_future = time.time() + 3600

    with monkeypatch.context() as mp:
        ec2_client = boto3.client("ec2")

        def fake_list_vpc_boxes(ec2_client, vpc_id):
            ret = []
            for box_dict in response.json["boxes"]:
                if "age" in box_dict:
                    box_dict.pop("age")
                box = Box(**box_dict)
                box.created_at = None
                ret.append(box)
            return ret

        mp.setattr(time, "time", lambda: the_future)
        mp.setattr(fuzzbucket.reaper, "list_vpc_boxes", fake_list_vpc_boxes)
        reap_response = fuzzbucket.reaper.reap_boxes(
            None, None, ec2_client=ec2_client, env={"CF_VPC": "vpc-fafafafafaf"}
        )
        assert reap_response["reaped_instance_ids"] == []

    with monkeypatch.context() as mp:
        ec2_client = boto3.client("ec2")

        def fake_list_vpc_boxes(ec2_client, vpc_id):
            ret = []
            for box_dict in response.json["boxes"]:
                if "age" in box_dict:
                    box_dict.pop("age")
                box = Box(**box_dict)
                box.ttl = None
                ret.append(box)
            return ret

        mp.setattr(time, "time", lambda: the_future)
        mp.setattr(fuzzbucket.reaper, "list_vpc_boxes", fake_list_vpc_boxes)
        reap_response = fuzzbucket.reaper.reap_boxes(
            None, None, ec2_client=ec2_client, env={"CF_VPC": "vpc-fafafafafaf"}
        )
        assert reap_response["reaped_instance_ids"] == []

    with monkeypatch.context() as mp:
        ec2_client = boto3.client("ec2")

        def fake_list_vpc_boxes(ec2_client, vpc_id):
            ret = []
            for box_dict in response.json["boxes"]:
                if "age" in box_dict:
                    box_dict.pop("age")
                box = Box(**box_dict)
                ret.append(box)
            return ret

        mp.setattr(time, "time", lambda: the_future)
        mp.setattr(fuzzbucket.reaper, "list_vpc_boxes", fake_list_vpc_boxes)
        reap_response = fuzzbucket.reaper.reap_boxes(
            None, None, ec2_client=ec2_client, env={"CF_VPC": "vpc-fafafafafaf"}
        )
        assert reap_response["reaped_instance_ids"] != []

    assert instance_id not in [
        box.instance_id
        for box in fuzzbucket.list_boxes_filtered(
            ec2_client, fuzzbucket.DEFAULT_FILTERS
        )
    ]


def test_box():
    box = Box(instance_id="i-fafafafafafafaf")
    assert box.age == "?"

    box.created_at = str(time.time() - 1000)
    for unit in ("d", "h", "m", "s"):
        assert box.age.count(unit) == 1

    assert "instance_id" in box.as_json()
    assert "age" in box.as_json()

    with pytest.raises(TypeError):
        Box(instance_id="i-fafafafbabacaca", frobs=9001)
