import base64
import json
import random
import time

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
    return {
        "CF_VPC": "vpc-fafafafafaf",
    }


@pytest.fixture
def pubkey():
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
def test_create_box(authd_event, env, monkeypatch, pubkey):
    client = boto3.client("ec2")
    with monkeypatch.context() as mp:
        mp.setattr(boxbot, "_fetch_first_github_key", lambda u: pubkey)
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
def test_delete_box(authd_event, env, monkeypatch, pubkey):
    client = boto3.client("ec2")
    with monkeypatch.context() as mp:
        mp.setattr(boxbot, "_fetch_first_github_key", lambda u: pubkey)
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


def test_box():
    box = boxbot.Box()
    box.instance_id = "i-fafafafafafafaf"
    assert box.age == "?"

    box.created_at = str(time.time() - 1000)
    assert box.age.startswith("0d5h")

    assert "instance_id" in box.as_json()
    assert "age" in box.as_json()
