import datetime
import os
import random
import typing

import flask
import flask_login
import pytest

os.environ["FUZZBUCKET_STAGE"] = "test"

import fuzzbucket.app


class TemplateResponse(typing.NamedTuple):
    template_name: str
    status_code: int


class FakeRequest(typing.NamedTuple):
    headers: dict[str, str]
    args: dict[str, str]
    environ: dict[str, str]
    body: typing.TextIO | None = None


class WrappedError(typing.NamedTuple):
    original_exception: Exception


AnyDict = dict[str, typing.Any]


@pytest.fixture
def app() -> flask.Flask:
    return fuzzbucket.app.create_app()


@pytest.fixture(autouse=True)
def resetti(app):
    from fuzzbucket import aws, flask_dance_storage

    os.environ.setdefault("FUZZBUCKET_DEFAULT_VPC", "vpc-fafafafaf")
    os.environ.setdefault("FUZZBUCKET_STAGE", "test")
    aws.get_dynamodb.cache_clear()
    aws.get_ec2_client.cache_clear()
    app.testing = True
    app.test_client_class = flask_login.FlaskLoginClient
    app.secret_key = f":hushed:-:open_mouth:-{random.randint(42, 666)}"
    session_storage = flask_dance_storage.FlaskDanceStorage(
        table_name=f"fuzzbucket-{os.getenv('FUZZBUCKET_STAGE')}-users"
    )
    app.config["session_storage"] = session_storage
    app.config["oauth_blueprint"].storage = session_storage


@pytest.fixture(scope="session", autouse=True)
def env_setup():
    for key, value in (
        ("FUZZBUCKET_FLASK_SECRET_KEY", "shhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"),
        ("FUZZBUCKET_AUTH_PROVIDER", "github-oauth"),
        ("FUZZBUCKET_GITHUB_OAUTH_CLIENT_ID", "abc123"),
        ("FUZZBUCKET_GITHUB_OAUTH_CLIENT_SECRET", "xyz456"),
        ("FUZZBUCKET_OAUTH_AUTH_URL", ""),
        ("FUZZBUCKET_OAUTH_BASE_URL", ""),
        ("FUZZBUCKET_OAUTH_CLIENT_ID", "abc123"),
        ("FUZZBUCKET_OAUTH_CLIENT_SECRET", "xyz456"),
        ("FUZZBUCKET_OAUTH_TOKEN_URL", ""),
        ("FUZZBUCKET_OAUTH_MAX_AGE", "90 days"),
        ("FUZZBUCKET_OAUTH_SCOPE", "openid"),
    ):
        os.environ.setdefault(key, value)


@pytest.fixture
def nowish() -> datetime.datetime:
    return datetime.datetime(2020, 3, 15, 11, 22, 4, 655788)


def setup_dynamodb_tables(dynamodb):
    image_aliases_table = f"fuzzbucket-{os.getenv('FUZZBUCKET_STAGE')}-image-aliases"
    table = dynamodb.create_table(
        AttributeDefinitions=[dict(AttributeName="alias", AttributeType="S")],
        KeySchema=[dict(AttributeName="alias", KeyType="HASH")],
        TableName=image_aliases_table,
        BillingMode="PAY_PER_REQUEST",
    )
    table.meta.client.get_waiter("table_exists").wait(TableName=image_aliases_table)

    for alias, ami in {
        "ubuntu18": "ami-fafafafafaf",
        "rhel8": "ami-fafafafafaa",
    }.items():
        table.put_item(Item=dict(user="pytest", alias=alias, ami=ami))

    users_table = f"fuzzbucket-{os.getenv('FUZZBUCKET_STAGE')}-users"
    table = dynamodb.create_table(
        AttributeDefinitions=[dict(AttributeName="user", AttributeType="S")],
        KeySchema=[dict(AttributeName="user", KeyType="HASH")],
        TableName=users_table,
        BillingMode="PAY_PER_REQUEST",
    )
    table.meta.client.get_waiter("table_exists").wait(TableName=users_table)

    for user, secret in {"pytest": "zzz", "nerf": "herder"}.items():
        table.put_item(Item=dict(user=user, secret=secret))


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


@pytest.fixture
def authd_headers() -> typing.List[typing.Tuple[str, str]]:
    return [("Fuzzbucket-User", "pytest"), ("Fuzzbucket-Secret", "zzz")]


@pytest.fixture
def fake_oauth_session():
    return FakeOAuthSession()


class FakeOAuthSession:
    def __init__(self):
        self.authorized = True
        self.responses = {
            "/user": {"login": "pytest"},
            "/user/orgs": [{"login": "frob"}],
            "userinfo": {"email": "pytest@example.org"},
        }
        self.next_json = None
        self._token = None

    @property
    def _client(self):
        return self

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
