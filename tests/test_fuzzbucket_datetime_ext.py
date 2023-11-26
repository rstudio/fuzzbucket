import datetime

import pytest

from fuzzbucket import datetime_ext


@pytest.mark.parametrize(
    ("input_string", "expected", "expect_error"),
    [
        pytest.param(
            "4:30:05",
            datetime.timedelta(hours=4, minutes=30, seconds=5),
            False,
            id="only_sexagesimal",
        ),
        pytest.param(
            "20:95",
            datetime.timedelta(minutes=20, seconds=95),
            False,
            id="short_sexagesimal",
        ),
        pytest.param("4 days", datetime.timedelta(days=4), False, id="days"),
        pytest.param("3 hours", datetime.timedelta(hours=3), False, id="hours"),
        pytest.param("3 minutes", datetime.timedelta(minutes=3), False, id="minutes"),
        pytest.param(
            "900.5 seconds", datetime.timedelta(seconds=900.5), False, id="seconds"
        ),
        pytest.param("2 week", datetime.timedelta(weeks=2), False, id="weeks"),
        pytest.param(
            "1 days, 1:10:00",
            datetime.timedelta(days=1, hours=1, minutes=10),
            False,
            id="stdlib_string",
        ),
        pytest.param(
            "10800", datetime.timedelta(seconds=10800.0), False, id="seconds_only"
        ),
        pytest.param("parrots", None, True, id="bogus"),
    ],
)
def test_parse_timedelta(input_string, expected, expect_error):
    if expect_error:
        with pytest.raises(ValueError):
            datetime_ext.parse_timedelta(input_string)
        return

    assert expected == datetime_ext.parse_timedelta(input_string)
