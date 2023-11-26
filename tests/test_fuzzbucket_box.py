import datetime

import pytest

from fuzzbucket import box, datetime_ext


def test_box(app):
    boxy = box.Box(instance_id="i-fafafafafafafaf")
    assert boxy.age is None

    boxy.created_at = str(
        (datetime_ext.utcnow() - datetime.timedelta(days=1, minutes=1)).timestamp()
    )
    assert boxy.age is not None
    assert boxy.age.startswith("1 day,")

    assert "instance_id" in boxy.as_json()
    assert "age" in boxy.as_json()
    assert "max_age" in boxy.as_json()

    with pytest.raises(TypeError):
        box.Box(instance_id="i-fafafafbabacaca", frobs=9001)  # type: ignore

    dumped = app.json.dumps(boxy)
    assert '"age":' in dumped
    assert '"max_age":' in dumped
