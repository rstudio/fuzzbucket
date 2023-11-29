import datetime
import typing

import boto3
import flask

import conftest
from fuzzbucket import aws, box, cfg, datetime_ext, reaper, user


def test_reap_boxes(
    app,
    dynamodb,
    ec2,
    fake_oauth_session,
    monkeypatch,
    pubkey,
):
    test_user = user.User(
        user_id="lordtestingham", secret="nonempty", token={"token": "wow"}
    )
    dynamodb.Table(cfg.USERS_TABLE).put_item(Item=test_user.as_item())

    fake_oauth_session.authorized = True
    fake_oauth_session.responses["/user"]["login"] = test_user.user_id

    if cfg.AUTH_PROVIDER == "oauth":
        monkeypatch.setattr(flask, "session", {"user": "lordtestingham"})

        def fake_describe_key_pairs():
            return {
                "KeyPairs": [
                    {
                        "KeyName": "lordTestingham",
                        "KeyPairId": "key-fafafafafafafafaf",
                        "KeyFingerprint": "ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa:ff:aa",
                    }
                ]
            }

        monkeypatch.setattr(ec2, "describe_key_pairs", fake_describe_key_pairs)

    def fake_describe_images(*_, **__):
        return {
            "Images": [
                {
                    "RootDeviceName": "/dev/xyz",
                    "BlockDeviceMappings": [
                        {"DeviceName": "/dev/xyz", "Ebs": {"VolumeSize": 9}}
                    ],
                }
            ]
        }

    monkeypatch.setattr(ec2, "describe_images", fake_describe_images)

    boxes: list[conftest.AnyDict]
    instance_id: str

    with monkeypatch.context() as mp:
        mp.setattr(aws, "fetch_first_compatible_github_key", lambda _: pubkey)

        with app.test_client(user=test_user) as c:
            response = c.post(
                "/box/",
                json={"ttl": "-1", "ami": "ami-fafafafafaf"},
                headers={
                    "fuzzbucket-secret": test_user.secret,
                    "fuzzbucket-user": test_user.user_id,
                },
            )

            assert response is not None
            assert "boxes" in typing.cast(conftest.AnyDict, response.json)

            boxes = typing.cast(conftest.AnyDict, response.json)["boxes"]

    assert len(boxes) > 0

    instance_id = boxes[0]["instance_id"]

    assert instance_id != ""

    the_future = datetime_ext.utcnow() + datetime.timedelta(hours=1)

    with monkeypatch.context() as mp:
        ec2_client = boto3.client("ec2")

        def fake_list_vpc_boxes(*_, **__):
            ret = []
            for box_dict in boxes:
                for virtual in ("age", "max_age"):
                    if virtual in box_dict:
                        box_dict.pop(virtual)
                boxy = box.Box(**box_dict)
                boxy.created_at = None
                ret.append(boxy)
            return ret

        mp.setattr(datetime_ext, "utcnow", lambda: the_future)
        mp.setattr(aws, "list_vpc_boxes", fake_list_vpc_boxes)
        mp.setenv("FUZZBUCKET_DEFAULT_VPC", "vpc-fafafafafaf")
        reap_response = reaper.reap_boxes(
            None,
            None,
            ec2_client=ec2_client,
        )
        assert reap_response["reaped_instance_ids"] == []

    with monkeypatch.context() as mp:
        ec2_client = boto3.client("ec2")

        def fake_list_vpc_boxes_2(*_, **__):
            ret = []
            for box_dict in boxes:
                for virtual in ("age", "max_age"):
                    if virtual in box_dict:
                        box_dict.pop(virtual)
                boxy = box.Box(**box_dict)
                boxy.ttl = None  # type: ignore
                ret.append(boxy)
            return ret

        mp.setattr(datetime_ext, "utcnow", lambda: the_future)
        mp.setattr(aws, "list_vpc_boxes", fake_list_vpc_boxes_2)
        mp.setenv("FUZZBUCKET_DEFAULT_VPC", "vpc-fafafafafaf")
        reap_response = reaper.reap_boxes(
            None,
            None,
            ec2_client=ec2_client,
        )
        assert reap_response["reaped_instance_ids"] == []

    with monkeypatch.context() as mp:
        ec2_client = boto3.client("ec2")

        def fake_list_vpc_boxes_3(*_, **__):
            ret = []
            for box_dict in boxes:
                for virtual in ("age", "max_age"):
                    if virtual in box_dict:
                        box_dict.pop(virtual)
                boxy = box.Box(**box_dict)
                ret.append(boxy)
            return ret

        mp.setattr(datetime_ext, "utcnow", lambda: the_future)
        mp.setattr(aws, "list_vpc_boxes", fake_list_vpc_boxes_3)
        mp.setenv("FUZZBUCKET_DEFAULT_VPC", "vpc-fafafafafaf")
        reap_response = reaper.reap_boxes(
            None,
            None,
            ec2_client=ec2_client,
        )
        assert reap_response["reaped_instance_ids"] != []

    assert instance_id not in [
        boxy.instance_id
        for boxy in aws.list_boxes_filtered(
            ec2_client, [dict(f) for f in aws.DEFAULT_FILTERS]
        )
    ]
