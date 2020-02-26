import json

import boto3

from moto import mock_ec2

import boxbot


@mock_ec2
def test_list_boxes():
    client = boto3.client("ec2")
    response = boxbot.list_boxes({}, None, client=client)
    assert response["statusCode"] == 200
    assert response["body"] is not None
    body = json.loads(response["body"])
    assert "instances" in body
    assert "Reservations" in body["instances"]
