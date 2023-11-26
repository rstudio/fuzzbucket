import os

import boto3
import botocore.exceptions
import pytest
from moto import mock_dynamodb, mock_ec2

import fuzzbucket.aws as aws
from conftest import setup_dynamodb_tables


def test_get_ec2_client(monkeypatch):
    state = {}

    def fake_client(name):
        state.update(name=name)
        return "client"

    monkeypatch.setattr(boto3, "client", fake_client)
    client = aws.get_ec2_client()
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

    aws.get_dynamodb.cache_clear()
    resource = aws.get_dynamodb()
    assert state["name"] == "dynamodb"
    assert resource == "resource"
    if offline:
        assert state["kwargs"]["region_name"] == "localhost"
        assert state["kwargs"]["endpoint_url"] == "http://localhost:8000"


@mock_ec2
def test_list_vpc_boxes(monkeypatch):
    state = {}

    def fake_list_boxes_filtered(ec2_client, filters):
        state.update(ec2_client=ec2_client, filters=filters)
        return ["ok"]

    monkeypatch.setattr(aws, "list_boxes_filtered", fake_list_boxes_filtered)

    ec2_client = {"ec2_client": "sure"}
    vpc_id = "vpc-fafafafaf"
    listed = aws.list_vpc_boxes(ec2_client, vpc_id)
    assert listed == ["ok"]
    assert state["ec2_client"] == ec2_client
    for default_filter in [dict(f) for f in aws.DEFAULT_FILTERS]:
        assert default_filter in state["filters"]
    assert {"Name": "vpc-id", "Values": [vpc_id]} in state["filters"]


@mock_dynamodb
@pytest.mark.parametrize(
    ("image_alias", "raises", "expected"),
    [
        pytest.param("noice", False, None, id="invalid"),
        pytest.param("rhel8", True, None, id="errored"),
        pytest.param("rhel8", False, "ami-fafafafafaa", id="valid"),
    ],
)
def test_resolve_ami_alias(monkeypatch, image_alias, raises, expected):
    monkeypatch.setenv("FUZZBUCKET_STAGE", "bogus")

    dynamodb = boto3.resource("dynamodb")
    monkeypatch.setattr(aws, "get_dynamodb", lambda: dynamodb)
    setup_dynamodb_tables(dynamodb)

    if raises:

        def boom(*_):
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": 1312, "Message": "nah"}}, "wut"  # type: ignore
            )

        monkeypatch.setattr(dynamodb, "Table", boom)

    response = aws.resolve_ami_alias(image_alias)
    assert response == expected


@pytest.mark.parametrize(
    ("raises", "api_response", "expected_key"),
    [
        pytest.param(
            False,
            [
                {"key": "ssh-ecdsagoop first"},
                {"key": "ssh-rsa second"},
                {"key": "ssh-rsa third"},
            ],
            "ssh-rsa second",
            id="3_keys",
        ),
        pytest.param(
            False,
            [
                {"key": "ssh-ecdsagoop first"},
                {"key": "ssh-nope second"},
                {"key": "ssh-ed25519 third"},
            ],
            "ssh-ed25519 third",
            id="3_keys_also",
        ),
        pytest.param(False, [{"key": "ssh-rsa first"}], "ssh-rsa first", id="1_key"),
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
def test_fetch_first_compatible_github_key(
    monkeypatch, raises, api_response, expected_key
):
    class FakeOAuthSession:
        def get(self, *_):
            if raises:
                raise ValueError("oh no")
            return self

        def json(self):
            return api_response

    monkeypatch.setattr(aws, "github", FakeOAuthSession())
    assert aws.fetch_first_compatible_github_key("user") == expected_key
