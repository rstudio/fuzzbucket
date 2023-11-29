import os
import re
import typing
import urllib.parse

from . import __version__, datetime_ext


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

    if value is not None and str(value).strip() != "":
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


STAGE: str = typing.cast(str, get("FUZZBUCKET_STAGE"))

ALLOWED_GITHUB_ORGS = tuple(getlist("FUZZBUCKET_ALLOWED_GITHUB_ORGS"))
AUTH_PROVIDER: str = typing.cast(
    str, get("FUZZBUCKET_AUTH_PROVIDER", default="github-oauth")
)
BRANDING: str = typing.cast(str, get("FUZZBUCKET_BRANDING"))
DEFAULT_HEADERS: tuple[tuple[str, str], ...] = (
    ("server", f"fuzzbucket/{__version__.__version__}"),
    ("fuzzbucket-region", str(get("FUZZBUCKET_REGION"))),
    ("fuzzbucket-version", __version__.__version__),
)
DEFAULT_INSTANCE_TAGS: tuple[dict[str, str], ...] = tuple(
    [
        dict(
            Key=urllib.parse.unquote(k.strip()),
            Value=urllib.parse.unquote(v.strip()),
        )
        for k, v in [
            pair.split(":", maxsplit=1)
            for pair in (get("FUZZBUCKET_DEFAULT_INSTANCE_TAGS") or "").split(",")
            if ":" in pair
        ]
    ]
)
DEFAULT_TTL = float(
    typing.cast(
        str,
        get("FUZZBUCKET_DEFAULT_TTL", default=str(3600 * 4)),
    )
)
IMAGE_ALIASES_TABLE = f"fuzzbucket-{STAGE}-image-aliases"
OAUTH_MAX_AGE = datetime_ext.parse_timedelta(
    typing.cast(
        str,
        get("FUZZBUCKET_OAUTH_MAX_AGE", default="1 day"),
    )
).total_seconds()
SECRET_TOKEN_SIZE_ENCODED = 42
SECRET_TOKEN_SIZE_PLAIN = 31
UNKNOWN_AUTH_PROVIDER: ValueError = ValueError(
    f"unknown auth provider {AUTH_PROVIDER!r}"
)
USERS_TABLE = f"fuzzbucket-{STAGE}-users"
