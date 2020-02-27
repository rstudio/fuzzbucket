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


@pytest.fixture
def env():
    return {"BOXBOT_VPC_ID": "vpc-fafafafafaf"}


@mock_ec2
def test_list_boxes(authd_event, env):
    client = boto3.client("ec2")
    response = boxbot.list_boxes(authd_event, None, client=client, env=env)
    assert response["statusCode"] == 200
    assert response["body"] is not None
    body = json.loads(response["body"])
    assert "boxes" in body
    assert body["boxes"] is not None


@mock_ec2
def test_list_boxes_forbidden(env):
    client = boto3.client("ec2")
    response = boxbot.list_boxes({}, None, client=client, env=env)
    assert response["statusCode"] == 403


@mock_ec2
def test_create_box(authd_event, env):
    client = boto3.client("ec2")
    response = boxbot.create_box(authd_event, None, client=client, env=env)
    assert response["statusCode"] == 200
    assert response["body"] is not None
    body = json.loads(response["body"])
    assert "boxes" in body
    assert body["boxes"] != []


@mock_ec2
def test_create_box_forbidden(env):
    client = boto3.client("ec2")
    response = boxbot.create_box({}, None, client=client, env=env)
    assert response["statusCode"] == 403


@mock_ec2
def test_delete_box(authd_event, env):
    client = boto3.client("ec2")
    response = boxbot.create_box(authd_event, None, client=client, env=env)
    assert response is not None
    assert "body" in response
    body = json.loads(response["body"])
    assert "boxes" in body
    event = {"pathParameters": {"id": body["boxes"][0]["instance_id"]}}
    event.update(**authd_event)
    response = boxbot.delete_box(event, None, client=client)
    assert response["statusCode"] == 204


@mock_ec2
def test_delete_box_forbidden(env):
    client = boto3.client("ec2")
    event = {"pathParameters": {"id": "i-fafafafafafaf"}}
    response = boxbot.delete_box(event, None, client=client, env=env)
    assert response["statusCode"] == 403
