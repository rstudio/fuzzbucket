import os
import re
import typing


def get(
    *keys: str, default: str | None = None, env: dict[str, str] | None = None
) -> str | None:
    env = env if env is not None else os.environ.copy()

    for key in keys:
        if key == "":
            continue

        value = env.get(key)

        if value is not None and str(value).strip() != "":
            return value

    return default


def getbool(
    *keys: str, default: bool = False, env: dict[str, str] | None = None
) -> bool:
    value = get(*keys, env=env)

    if value is not None:
        return str(value).lower() in ("true", "ok", "yes", "on", "1")

    return default


def getlist(
    *keys: str, default: tuple[str, ...] = (), env: dict[str, str] | None = None
) -> list[str]:
    value = [
        s.strip()
        for s in re.split("[ ,]", (get(*keys, env=env) or ""))
        if s.strip() != ""
    ]

    if len(value) != 0:
        return value

    return list(default)


def getdict(
    *keys: str, default: dict[str, str] | None = None, env: dict[str, str] | None = None
) -> dict[str, str]:
    as_list = getlist(*keys, env=env)
    if len(as_list) == 0:
        return default or {}

    return dict(
        [(k.strip(), v.strip()) for k, v in [pair.split(":", 1) for pair in as_list]]
    )


def vpc_id(env: dict[str, str] | None = None) -> str:
    return typing.cast(
        str,
        get(
            "FUZZBUCKET_DEFAULT_VPC",
            default="NOTSET",
            env=env,
        ),
    )
