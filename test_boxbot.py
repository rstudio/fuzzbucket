import json
import random

import boxbot


def test_box_please():
    fancy_value = random.randint(-42, 42)
    response = boxbot.box_please({"fancy": fancy_value}, None)
    assert response["statusCode"] == 200
    assert response["body"] is not None
    body = json.loads(response["body"])
    assert "this cow" in body["message"]
    assert "fancy" in body["input"]
    assert body["input"]["fancy"] == fancy_value
