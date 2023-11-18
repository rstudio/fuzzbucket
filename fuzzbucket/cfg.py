import os
import typing

from . import NoneEnv, NoneString


def get(*keys: str, default: NoneString = None, env: NoneEnv = None) -> NoneString:
    env = env if env is not None else os.environ.copy()

    for key in keys:
        if key == "":
            continue

        value = env.get(key)

        if value is not None and str(value).strip() != "":
            return value

    return default


def getbool(*keys: str, default: bool = False, env: NoneEnv = None) -> bool:
    value = get(*keys, env=env)

    if value is not None:
        return str(value).lower() in ("true", "ok", "yes", "on", "1")

    return default


def getlist(
    *keys: str, default: tuple[str, ...] = (), env: NoneEnv = None
) -> list[str]:
    value = [
        s.strip() for s in (get(*keys, env=env) or "").split(" ") if s.strip() != ""
    ]

    if len(value) != 0:
        return value

    return list(default)


def vpc_id(env: NoneEnv = None) -> str:
    return typing.cast(
        str,
        get(
            "FUZZBUCKET_DEFAULT_VPC",
            "CF_VPC" if include_cf_defaults(env) else "",
            default="NOTSET",
            env=env,
        ),
    )


def include_cf_defaults(env: NoneEnv = None) -> bool:
    return getbool("FUZZBUCKET_INCLUDE_CF_DEFAULTS", default=True, env=env)
