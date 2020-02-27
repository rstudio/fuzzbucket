import base64
import json

import boto3
import pytest

from moto import mock_ec2

import boxbot


@pytest.fixture
def authd_event():
    return {
        "headers": {"Authorization": base64.b64encode(b"pytest:zzz").decode("utf-8")}
    }


@mock_ec2
def test_list_boxes(authd_event):
    client = boto3.client("ec2")
    response = boxbot.list_boxes(authd_event, None, client=client)
    assert response["statusCode"] == 200
    assert response["body"] is not None
    body = json.loads(response["body"])
    assert "instances" in body
    assert body["instances"] is not None


@mock_ec2
def test_list_boxes_forbidden():
    client = boto3.client("ec2")
    response = boxbot.list_boxes({}, None, client=client)
    assert response["statusCode"] == 403


@mock_ec2
@pytest.mark.skip(reason="subnet problems")
def test_create_box(authd_event):
    client = boto3.client("ec2")
    response = boxbot.create_box(authd_event, None, client=client)
    assert response["statusCode"] == 200
    assert response["body"] is not None
    body = json.loads(response["body"])
    assert "Instances" in body


@mock_ec2
def test_create_box_forbidden():
    client = boto3.client("ec2")
    response = boxbot.create_box({}, None, client=client)
    assert response["statusCode"] == 403
