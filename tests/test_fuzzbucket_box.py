import datetime

import pytest

from fuzzbucket.app import create_app
from fuzzbucket.box import Box
from fuzzbucket.datetime_ext import utcnow


def test_box():
    box = Box(instance_id="i-fafafafafafafaf")
    assert box.age is None

    box.created_at = str((utcnow() - datetime.timedelta(days=1, minutes=1)).timestamp())
    assert box.age is not None
    assert box.age.startswith("1 day,")

    assert "instance_id" in box.as_json()
    assert "age" in box.as_json()
    assert "max_age" in box.as_json()

    with pytest.raises(TypeError):
        Box(instance_id="i-fafafafbabacaca", frobs=9001)  # type: ignore

    dumped = create_app().json.dumps(box)
    assert '"age":' in dumped
    assert '"max_age":' in dumped
