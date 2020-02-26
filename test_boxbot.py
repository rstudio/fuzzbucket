import json

import boto3

from moto import mock_ec2

import boxbot


@mock_ec2
def test_box_please():
    client = boto3.client("ec2")
    response = boxbot.box_please({}, None, client=client)
    assert response["statusCode"] == 200
    assert response["body"] is not None
    body = json.loads(response["body"])
    assert "instances" in body
    assert "Reservations" in body["instances"]
