import datetime


def parse_timedelta(as_string: str) -> datetime.timedelta:
    pairs = as_string.strip().lower().replace(",", "").split()
    sexagesimal_part = None

    if len(pairs) == 1:
        if ":" in pairs[0]:
            sexagesimal_part = pairs[0]
        else:
            return datetime.timedelta(seconds=float(pairs[0]))

    elif len(pairs) % 2 != 0:
        if ":" in pairs[-1]:
            sexagesimal_part = pairs[-1]
        else:
            raise ValueError(
                f"timedelta string {as_string!r} is not in an understandable format"
            )

    kwargs = _timedelta_kwargs_from_pairs(pairs)
    if sexagesimal_part is not None:
        kwargs.update(_timedelta_kwargs_from_sexagesimal(sexagesimal_part))

    unknown_keys = set(kwargs.keys()).difference(
        set(
            [
                "days",
                "hours",
                "minutes",
                "seconds",
                "weeks",
            ]
        )
    )
    if len(unknown_keys) > 0:
        raise ValueError(f"unknown timedelta keys {unknown_keys!r}")

    return datetime.timedelta(
        days=kwargs.get("days", 0),
        hours=kwargs.get("hours", 0),
        minutes=kwargs.get("minutes", 0),
        seconds=kwargs.get("seconds", 0),
        weeks=kwargs.get("weeks", 0),
    )


def _reverse_map_float(el: tuple[str, str]) -> tuple[str, float]:
    return (el[1].rstrip("s")) + "s", float(el[0])


def _timedelta_kwargs_from_pairs(pairs: list[str]) -> dict[str, float]:
    as_iter = iter(pairs)
    return dict(map(_reverse_map_float, list(zip(as_iter, as_iter))))


def _timedelta_kwargs_from_sexagesimal(
    sexagesimal_string: str,
) -> dict[str, float]:
    return dict(
        map(
            _reverse_map_float,
            list(
                zip(
                    reversed(
                        [p.strip() for p in sexagesimal_string.strip().split(":")]
                    ),
                    ["seconds", "minutes", "hours"],
                )
            ),
        )
    )


def utcnow() -> datetime.datetime:
    return datetime.datetime.utcnow()
