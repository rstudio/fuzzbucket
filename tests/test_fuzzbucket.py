import base64
import collections
import json
import os
import random
import re
import time
import typing

import boto3
import botocore.exceptions
import pytest

from flask import Response
from moto import mock_ec2, mock_dynamodb2
from werkzeug.exceptions import InternalServerError

import fuzzbucket
import fuzzbucket.app
import fuzzbucket.flask_dance_storage
import fuzzbucket.reaper

from fuzzbucket.app import app
from fuzzbucket.box import Box

TemplateResponse = collections.namedtuple(
    "TemplateResponse", ("template_name", "status_code")
)
FakeRequest = collections.namedtuple(
    "FakeRequest", ("headers", "args", "body", "environ")
)
WrappedError = collections.namedtuple("WrappedError", ("original_exception",))


@pytest.fixture(autouse=True)
def resetti():
    os.environ.setdefault("CF_VPC", "vpc-fafafafaf")
    fuzzbucket.get_dynamodb.cache_clear()
    fuzzbucket.get_ec2_client.cache_clear()
    fuzzbucket.app.app.testing = True
    fuzzbucket.app.app.secret_key = f":hushed:-:open_mouth:-{random.randint(42, 666)}"
    gh_storage = fuzzbucket.flask_dance_storage.FlaskDanceStorage(
        table_name=os.getenv("FUZZBUCKET_USERS_TABLE_NAME")
    )
    fuzzbucket.app.app.config["gh_storage"] = gh_storage
    fuzzbucket.app.app.config["gh_blueprint"].storage = gh_storage


@pytest.fixture
def authd_headers() -> typing.List[typing.Tuple[str, str]]:
    return [("Fuzzbucket-User", "pytest"), ("Fuzzbucket-Secret", "zzz")]


@pytest.fixture
def fake_github():
    class FakeGithub:
        def __init__(self):
            self.authorized = True
            self.responses = {
                "/user": {"login": "pytest"},
                "/user/orgs": [{"login": "frob"}],
            }
            self.next_json = None
            self._token = None

        @property
        def token(self):
            return self._token

        @token.setter
        def token(self, value):
            self._token = value

        @token.deleter
        def token(self):
            self._token = None

        def get(self, path):
            self.next_json = self.responses.get(path)
            return self

        def json(self):
            response = self.next_json
            self.next_json = None
            return response

    return FakeGithub()


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
    image_aliases_table = os.getenv("FUZZBUCKET_IMAGE_ALIASES_TABLE_NAME")
    table = dynamodb.create_table(
        AttributeDefinitions=[dict(AttributeName="alias", AttributeType="S")],
        KeySchema=[dict(AttributeName="alias", KeyType="HASH")],
        TableName=image_aliases_table,
    )
    table.meta.client.get_waiter("table_exists").wait(TableName=image_aliases_table)

    for alias, ami in {
        "ubuntu18": "ami-fafafafafaf",
        "rhel8": "ami-fafafafafaa",
    }.items():
        table.put_item(Item=dict(user="pytest", alias=alias, ami=ami))

    users_table = os.getenv("FUZZBUCKET_USERS_TABLE_NAME")
    table = dynamodb.create_table(
        AttributeDefinitions=[dict(AttributeName="user", AttributeType="S")],
        KeySchema=[dict(AttributeName="user", KeyType="HASH")],
        TableName=users_table,
    )
    table.meta.client.get_waiter("table_exists").wait(TableName=users_table)

    for user, secret in {"pytest": "zzz", "nerf": "herder"}.items():
        table.put_item(Item=dict(user=user, secret=secret))


def test_deferred_app():
    state = {}

    def fake_start_response(status, headers):
        state.update(status=status, headers=headers)

    response = fuzzbucket.deferred_app(
        {
            "BUSTED_ENV": True,
            "REQUEST_METHOD": "BORK",
            "SERVER_NAME": "nope.example.com",
            "SERVER_PORT": "64434",
            "wsgi.url_scheme": "http",
        },
        fake_start_response,
    )
    assert response is not None
    assert state["status"] == "405 METHOD NOT ALLOWED"
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
        return json.dumps(thing, cls=fuzzbucket.AsJSONEncoder)

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
    ("exc", "check_html", "err_match"),
    [
        pytest.param(
            WrappedError(ValueError("not enough pylons")),
            True,
            "^NOPE=.*not enough pylons",
            id="wrapped",
        ),
        pytest.param(
            InternalServerError(
                "spline reticulation overload",
                response=Response(content_type="application/json"),
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

    monkeypatch.setattr(fuzzbucket.app, "render_template", fake_render_template)

    if check_html:
        assert fuzzbucket.app.handle_500(exc) == ("RENDERED", 500)
        assert "kwargs" in state
        assert "error" in state["kwargs"]
        assert re.search(err_match, state["kwargs"]["error"]) is not None
    else:
        body, status = fuzzbucket.app.handle_500(exc)
        assert status == 500
        body_json = json.loads(body)
        assert "error" in body_json
        assert re.search(err_match, body_json["error"]) is not None


@pytest.mark.parametrize(
    (
        "session_user",
        "header_user",
        "arg_user",
        "github_authd",
        "user_response",
        "expected_token",
        "expected_user",
    ),
    [
        pytest.param(
            "session-pytest",
            None,
            None,
            True,
            {"login": "session-pytest"},
            "unchanged",
            "session-pytest",
            id="happy_session",
        ),
        pytest.param(
            None,
            "header-pytest",
            None,
            True,
            {"login": "header-pytest"},
            "unchanged",
            "header-pytest",
            id="happy_header",
        ),
        pytest.param(
            None,
            None,
            "arg-pytest",
            True,
            {"login": "arg-pytest"},
            "unchanged",
            "arg-pytest",
            id="happy_arg",
        ),
        pytest.param(
            None, None, None, False, {}, "unchanged", None, id="happy_nothing",
        ),
        pytest.param(
            "elmer", None, None, True, {"login": "bugs"}, None, None, id="mismatched",
        ),
    ],
)
def test_set_user(
    monkeypatch,
    fake_github,
    session_user,
    header_user,
    arg_user,
    github_authd,
    user_response,
    expected_token,
    expected_user,
):
    monkeypatch.setattr(fuzzbucket.app, "github", fake_github)
    fake_github.responses["/user"] = user_response
    fake_github.authorized = github_authd
    fake_github.token = "unchanged"
    fake_session = {"user": session_user}
    monkeypatch.setattr(fuzzbucket.app, "session", fake_session)
    monkeypatch.setattr(
        fuzzbucket.app,
        "request",
        FakeRequest({"Fuzzbucket-User": header_user}, {"user": arg_user}, None, {}),
    )
    fuzzbucket.app.set_user()
    assert fake_github.token == expected_token
    assert fake_session.get("user") == expected_user


@pytest.mark.parametrize(
    (
        "github_authd",
        "session_user",
        "user_response",
        "secret_header",
        "db_secret",
        "expected",
    ),
    [
        pytest.param(
            True,
            "pytest",
            {"login": "pytest"},
            "verysecret",
            "verysecret",
            True,
            id="happy",
        ),
        pytest.param(
            True,
            "pytest",
            {"login": "pytest"},
            "verysecret",
            "oh no",
            False,
            id="mismatched_db_secret",
        ),
        pytest.param(
            True,
            "pytest",
            {"login": "pytest"},
            "well then",
            "verysecret",
            False,
            id="mismatched_header_secret",
        ),
        pytest.param(
            True,
            "pytest",
            {"login": "founderman"},
            "verysecret",
            "verysecret",
            False,
            id="mismatched_github_user",
        ),
        pytest.param(
            True,
            "superperson",
            {"login": "pytest"},
            "verysecret",
            "verysecret",
            False,
            id="mismatched_session_user",
        ),
        pytest.param(
            False,
            "pytest",
            {"login": "pytest"},
            "verysecret",
            "verysecret",
            False,
            id="github_unauthorized",
        ),
    ],
)
def test_is_fully_authd(
    monkeypatch,
    fake_github,
    github_authd,
    session_user,
    user_response,
    secret_header,
    db_secret,
    expected,
):
    monkeypatch.setattr(fuzzbucket.app, "github", fake_github)
    fake_github.responses["/user"] = user_response
    fake_github.authorized = github_authd
    monkeypatch.setattr(fuzzbucket.app, "session", {"user": session_user})
    monkeypatch.setattr(
        fuzzbucket.app,
        "request",
        FakeRequest({"Fuzzbucket-Secret": secret_header}, {}, None, {}),
    )

    with app.app_context():
        monkeypatch.setattr(app.config["gh_storage"], "secret", lambda: db_secret)
        assert fuzzbucket.app.is_fully_authd() == expected


def test__login(monkeypatch):
    session = {}
    monkeypatch.setattr(fuzzbucket.app, "session", session)

    response = None
    with app.test_client() as c:
        response = c.get("/_login?user=pytest")

    assert response is not None
    assert response.status_code == 302
    assert "Location" in response.headers
    assert "user" in session
    assert session["user"] == "pytest"


@pytest.mark.parametrize(
    ("allowed_orgs", "orgs_response", "raises", "expected"),
    [
        pytest.param(
            "frobs globs",
            [{"login": "frobs"}],
            False,
            TemplateResponse("auth_complete.html", 200),
            id="happy",
        ),
        pytest.param(
            "frobs globs",
            [],
            False,
            TemplateResponse("error.html", 403),
            id="forbidden",
        ),
        pytest.param(
            "frobs globs",
            {"message": "now you have gone and also done it"},
            False,
            TemplateResponse("error.html", 503),
            id="github_err",
        ),
        pytest.param(
            "blubs glubs",
            [{"login": "blubs"}],
            True,
            TemplateResponse("error.html", 404),
            id="no_secret_err",
        ),
    ],
)
def test_auth_complete(
    monkeypatch, fake_github, allowed_orgs, orgs_response, raises, expected
):
    state = {}

    def fake_render_template(template_name, **kwargs):
        state.update(template_name=template_name, kwargs=kwargs)
        return "RENDERED"

    monkeypatch.setattr(fuzzbucket.app, "render_template", fake_render_template)
    monkeypatch.setattr(fuzzbucket.app, "github", fake_github)
    monkeypatch.setattr(fuzzbucket.app, "session", {"user": "pytest"})
    fake_github.responses["/user/orgs"] = orgs_response
    monkeypatch.setenv("FUZZBUCKET_ALLOWED_GITHUB_ORGS", allowed_orgs)

    if raises:

        def fake_secret():
            raise ValueError("no secret")

        monkeypatch.setattr(app.config["gh_storage"], "secret", fake_secret)

    response = None
    with app.test_client() as c:
        response = c.get("/auth-complete")

    assert response is not None
    assert not response.is_json
    assert response.status_code == expected.status_code
    assert state["template_name"] == expected.template_name


@pytest.mark.parametrize(
    ("authd", "expected"),
    [pytest.param(True, 200, id="happy",), pytest.param(False, 403, id="forbidden")],
)
@mock_ec2
@mock_dynamodb2
def test_list_boxes(authd_headers, monkeypatch, authd, expected):
    dynamodb = boto3.resource("dynamodb")
    setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "get_ec2_client", lambda: boto3.client("ec2"))
    monkeypatch.setattr(fuzzbucket.app, "is_fully_authd", lambda: authd)

    response = None
    with app.test_client() as c:
        response = c.get("/", headers=authd_headers)
    assert response is not None
    assert response.status_code == expected
    if authd:
        assert response.json is not None
        assert "boxes" in response.json
        assert response.json["boxes"] is not None


@pytest.mark.parametrize(
    ("authd", "expected"),
    [pytest.param(True, 201, id="happy",), pytest.param(False, 403, id="forbidden")],
)
@mock_ec2
@mock_dynamodb2
def test_create_box(authd_headers, monkeypatch, pubkey, authd, expected):
    monkeypatch.setattr(fuzzbucket.app, "get_ec2_client", lambda: boto3.client("ec2"))
    dynamodb = boto3.resource("dynamodb")
    setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(
        fuzzbucket.flask_dance_storage, "get_dynamodb", lambda: dynamodb
    )
    monkeypatch.setattr(fuzzbucket.app, "is_fully_authd", lambda: authd)

    response = None
    with monkeypatch.context() as mp:
        mp.setattr(fuzzbucket.app, "_fetch_first_github_key", lambda u: pubkey)
        with app.test_client() as c:
            response = c.post(
                "/box", json={"ami": "ami-fafafafafaf"}, headers=authd_headers,
            )
    assert response is not None
    assert response.status_code == expected
    if authd:
        assert response.json is not None
        assert "boxes" in response.json
        assert response.json["boxes"] != []


@pytest.mark.parametrize(
    ("authd", "expected"),
    [pytest.param(True, 204, id="happy",), pytest.param(False, 403, id="forbidden")],
)
@mock_ec2
@mock_dynamodb2
def test_delete_box(authd_headers, monkeypatch, pubkey, authd, expected):
    ec2_client = boto3.client("ec2")
    monkeypatch.setattr(fuzzbucket.app, "get_ec2_client", lambda: ec2_client)
    dynamodb = boto3.resource("dynamodb")
    setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(
        fuzzbucket.flask_dance_storage, "get_dynamodb", lambda: dynamodb
    )
    monkeypatch.setattr(fuzzbucket.app, "is_fully_authd", lambda: True)

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

        def fake_describe_instances(*_args, **_kwargs):
            return all_instances

        monkeypatch.setattr(
            ec2_client, "describe_instances", fake_describe_instances,
        )
        monkeypatch.setattr(fuzzbucket.app, "is_fully_authd", lambda: authd)
        response = c.delete(
            f'/box/{response.json["boxes"][0]["instance_id"]}', headers=authd_headers,
        )
        assert response.status_code == expected


@mock_ec2
def test_delete_box_not_yours(monkeypatch, authd_headers, fake_github):
    def fake_list_user_boxes(*_):
        return []

    monkeypatch.setattr(fuzzbucket.app, "list_user_boxes", fake_list_user_boxes)
    monkeypatch.setattr(fuzzbucket.app, "is_fully_authd", lambda: True)
    monkeypatch.setattr(fuzzbucket.app, "github", fake_github)

    response = None

    with app.test_client() as c:
        response = c.delete("/box/i-fafababacaca", headers=authd_headers)

    assert response is not None
    assert response.status_code == 403
    assert "error" in response.json
    assert response.json["error"] == "no touching"


@pytest.mark.parametrize(
    ("authd", "expected"),
    [pytest.param(True, 204, id="happy",), pytest.param(False, 403, id="forbidden")],
)
@mock_ec2
@mock_dynamodb2
def test_reboot_box(authd_headers, monkeypatch, pubkey, authd, expected):
    ec2_client = boto3.client("ec2")
    monkeypatch.setattr(fuzzbucket.app, "get_ec2_client", lambda: ec2_client)
    dynamodb = boto3.resource("dynamodb")
    setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(
        fuzzbucket.flask_dance_storage, "get_dynamodb", lambda: dynamodb
    )
    monkeypatch.setattr(fuzzbucket.app, "is_fully_authd", lambda: True)

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
            mp.setattr(fuzzbucket.app, "is_fully_authd", lambda: authd)
            response = c.post(
                f'/reboot/{response.json["boxes"][0]["instance_id"]}',
                headers=authd_headers,
            )
            assert response.status_code == expected


@mock_ec2
def test_reboot_box_not_yours(monkeypatch):
    def fake_list_user_boxes(*_):
        return []

    monkeypatch.setattr(fuzzbucket.app, "list_user_boxes", fake_list_user_boxes)
    monkeypatch.setattr(fuzzbucket.app, "is_fully_authd", lambda: True)

    response = None
    with app.test_client() as c:
        response = c.post("/reboot/i-fafafafaf")
    assert response is not None
    assert response.status_code == 403
    assert "error" in response.json
    assert response.json["error"] == "no touching"


@pytest.mark.parametrize(
    ("authd", "expected"),
    [pytest.param(True, 200, id="happy",), pytest.param(False, 403, id="forbidden")],
)
@mock_dynamodb2
def test_list_image_aliases(authd_headers, monkeypatch, authd, expected):
    dynamodb = boto3.resource("dynamodb")
    setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "is_fully_authd", lambda: authd)

    response = None
    with app.test_client() as c:
        response = c.get("/image-alias", headers=authd_headers)
    assert response is not None
    assert response.status_code == expected


@pytest.mark.parametrize(
    ("authd", "expected"),
    [pytest.param(True, 201, id="happy",), pytest.param(False, 403, id="forbidden")],
)
@mock_dynamodb2
def test_create_image_alias(authd_headers, monkeypatch, authd, expected):
    dynamodb = boto3.resource("dynamodb")
    setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "is_fully_authd", lambda: authd)

    response = None
    with app.test_client() as c:
        response = c.post(
            "/image-alias",
            json={"alias": "yikes", "ami": "ami-fafababacaca"},
            headers=authd_headers,
        )
    assert response is not None
    assert response.status_code == expected


@mock_dynamodb2
def test_create_image_alias_not_json(authd_headers, monkeypatch):
    dynamodb = boto3.resource("dynamodb")
    setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "is_fully_authd", lambda: True)

    response = None
    with app.test_client() as c:
        response = c.post("/image-alias", data="HAY", headers=authd_headers,)
    assert response is not None
    assert response.status_code == 400


@pytest.mark.parametrize(
    ("authd", "expected"),
    [pytest.param(True, 204, id="happy"), pytest.param(False, 403, id="forbidden")],
)
@mock_dynamodb2
def test_delete_image_alias(authd_headers, monkeypatch, authd, expected):
    dynamodb = boto3.resource("dynamodb")
    setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "is_fully_authd", lambda: authd)

    response = None
    with app.test_client() as c:
        response = c.delete("/image-alias/ubuntu18", headers=authd_headers)
    assert response is not None
    assert response.status_code == expected


@mock_dynamodb2
def test_delete_image_alias_no_alias(authd_headers, monkeypatch):
    dynamodb = boto3.resource("dynamodb")
    setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "is_fully_authd", lambda: True)

    response = None
    with app.test_client() as c:
        response = c.delete("/image-alias/nah", headers=authd_headers)
    assert response is not None
    assert response.status_code == 404


@mock_dynamodb2
def test_delete_image_alias_not_yours(monkeypatch):
    dynamodb = boto3.resource("dynamodb")
    setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "is_fully_authd", lambda: True)

    response = None
    with app.test_client() as c:
        response = c.delete(
            "/image-alias/ubuntu18",
            headers=[("Authorization", base64.b64encode(b"jag:wagon").decode("utf-8"))],
        )
    assert response is not None
    assert response.status_code == 403
    assert "error" in response.json
    assert response.json["error"] == "no touching"


@mock_dynamodb2
@pytest.mark.parametrize(
    ("image_alias", "raises", "expected"),
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
    ("raises", "api_response", "expected_key"),
    [
        pytest.param(
            False,
            [{"key": "first"}, {"key": "second"}, {"key": "third"}],
            "first",
            id="3_keys",
        ),
        pytest.param(False, [{"key": "first"}], "first", id="1_key"),
        pytest.param(False, [], "", id="empty"),
        pytest.param(
            True,
            [{"key": "first"}, {"key": "second"}, {"key": "third"}],
            "",
            id="err_3_keys",
        ),
        pytest.param(True, [{"key": "first"}], "", id="err_1_key"),
        pytest.param(True, [], "", id="err_empty"),
    ],
)
def test_fetch_first_github_key(monkeypatch, raises, api_response, expected_key):
    class FakeGithub:
        def get(self, *_):
            if raises:
                raise ValueError("oh no")
            return self

        def json(self):
            return api_response

    monkeypatch.setattr(fuzzbucket.app, "github", FakeGithub())
    assert fuzzbucket.app._fetch_first_github_key("user") == expected_key


@mock_ec2
@mock_dynamodb2
def test_reap_boxes(authd_headers, monkeypatch, pubkey):
    monkeypatch.setattr(fuzzbucket.app, "get_ec2_client", lambda: boto3.client("ec2"))
    monkeypatch.setattr(
        fuzzbucket.reaper, "get_ec2_client", lambda: boto3.client("ec2")
    )
    dynamodb = boto3.resource("dynamodb")
    setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(fuzzbucket.app, "get_dynamodb", lambda: dynamodb)
    monkeypatch.setattr(
        fuzzbucket.flask_dance_storage, "get_dynamodb", lambda: dynamodb
    )
    monkeypatch.setattr(fuzzbucket.app, "is_fully_authd", lambda: True)

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


@pytest.mark.parametrize(
    ("user", "token", "raises", "expected"),
    [
        pytest.param(
            "nonaps",
            "jagwagon9000",
            False,
            {"user": "nonaps", "token": "jagwagon9000"},
            id="happy",
        ),
        pytest.param(None, "busytown1999", True, {}, id="no_user"),
    ],
)
@mock_dynamodb2
def test_flask_dance_storage(monkeypatch, user, token, raises, expected):
    dynamodb = boto3.resource("dynamodb")
    setup_dynamodb_tables(dynamodb)
    monkeypatch.setattr(
        fuzzbucket.flask_dance_storage, "get_dynamodb", lambda: dynamodb
    )
    monkeypatch.setattr(fuzzbucket.flask_dance_storage, "session", {"user": user})

    storage = fuzzbucket.flask_dance_storage.FlaskDanceStorage(
        os.getenv("FUZZBUCKET_USERS_TABLE_NAME")
    )
    if raises:
        with pytest.raises(ValueError):
            storage.set(None, token)
        with pytest.raises(ValueError):
            storage.delete(None)
        assert storage.get(None) is None
        assert storage.secret() is None
    else:
        storage.set(None, token)
        actual = storage.dump()
        for key, value in expected.items():
            assert key in actual
            assert actual[key] == value
        storage.delete(None)
        assert storage.get(None) is None
        assert storage.secret() is None
