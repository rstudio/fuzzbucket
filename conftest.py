import datetime
import os
import random
import secrets
import typing

import boto3
import boto3.exceptions
import flask_login
import moto
import pytest

os.environ.update(
    FUZZBUCKET_STAGE="test",
    FUZZBUCKET_DEFAULT_VPC="vpc-fafafafaf",
    POWERTOOLS_LOG_LEVEL="DEBUG",
    POWERTOOLS_DEV="true",
    POWERTOOLS_DEBUG="true",
    AWS_ACCESS_KEY_ID="testing",
    AWS_SECRET_ACCESS_KEY="testing",
    AWS_SECURITY_TOKEN="testing",
    AWS_SESSION_TOKEN="testing",
    AWS_DEFAULT_REGION="us-east-1",
)

import fuzzbucket.app
from fuzzbucket import cfg

AnyDict = dict[str, typing.Any]


class TestClient(flask_login.FlaskLoginClient):
    def __init__(self, *args, **kwargs):
        user = kwargs.get("user")

        super().__init__(*args, **kwargs)

        if user is not None:
            with self.session_transaction() as sess:
                sess["user"] = user.user_id


@pytest.fixture
def app():
    inst = fuzzbucket.app.create_app()
    inst.testing = True
    inst.test_client_class = TestClient
    inst.secret_key = f":hushed:-:open_mouth:-{random.randint(42, 666)}"

    with inst.app_context():
        yield inst


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


@pytest.fixture(scope="function")
def dynamodb(fake_users, monkeypatch):
    from fuzzbucket import aws

    with moto.mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        setup_dynamodb_tables(ddb, fake_users)

        with monkeypatch.context() as mp:
            mp.setattr(aws, "get_dynamodb", lambda: ddb)

            yield ddb


@pytest.fixture(scope="function")
def ec2(monkeypatch):
    from fuzzbucket import aws

    with moto.mock_aws():
        ec2c = boto3.client("ec2", region_name="us-east-1")

        with monkeypatch.context() as mp:
            mp.setattr(aws, "get_ec2_client", lambda: ec2c)

            yield ec2c


def setup_dynamodb_tables(ddb, fake_users):
    def ensure_image_aliases_table():
        try:
            return ddb.create_table(
                AttributeDefinitions=[dict(AttributeName="alias", AttributeType="S")],
                KeySchema=[dict(AttributeName="alias", KeyType="HASH")],
                TableName=cfg.IMAGE_ALIASES_TABLE,
                BillingMode="PAY_PER_REQUEST",
            )
        except Exception:
            return ddb.Table(cfg.IMAGE_ALIASES_TABLE)

    image_aliases_table = ensure_image_aliases_table()
    image_aliases_table.meta.client.get_waiter("table_exists").wait(
        TableName=cfg.IMAGE_ALIASES_TABLE
    )

    for alias, ami in {
        "ubuntu18": "ami-fafafafafaf",
        "rhel8": "ami-fafafafafaa",
    }.items():
        image_aliases_table.put_item(Item=dict(user="pytest", alias=alias, ami=ami))

    def ensure_users_table():
        try:
            return ddb.create_table(
                AttributeDefinitions=[dict(AttributeName="user", AttributeType="S")],
                KeySchema=[dict(AttributeName="user", KeyType="HASH")],
                TableName=cfg.USERS_TABLE,
                BillingMode="PAY_PER_REQUEST",
            )
        except Exception:
            return ddb.Table(cfg.USERS_TABLE)

    users_table = ensure_users_table()
    users_table.meta.client.get_waiter("table_exists").wait(TableName=cfg.USERS_TABLE)

    for user, secret in fake_users.items():
        users_table.put_item(
            Item=dict(user=user, secret=secret, token=dict(token="OK"))
        )


@pytest.fixture
def fake_users():
    suffix = secrets.token_urlsafe(11)

    return {
        k: k + suffix
        for k in (
            "pytest",
            "nerf",
            "lordtestingham",
            "rumples",
            "philobuster",
            "slimer",
            "charizard",
        )
    }


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


@pytest.fixture
def fake_oauth_session(monkeypatch):
    sess = FakeOAuthSession()

    import flask_dance.contrib.github

    from fuzzbucket import g
    from fuzzbucket.blueprints import oauth

    with monkeypatch.context() as mp:
        mp.setattr(flask_dance.contrib.github, "github", sess)
        mp.setattr(oauth.bp, "session", sess)
        mp.setattr(g, "oauth_session", sess)

        yield sess
