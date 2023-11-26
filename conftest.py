import datetime
import os

import pytest

os.environ["FUZZBUCKET_STAGE"] = "test"


@pytest.fixture(scope="session", autouse=True)
def env_setup():
    for key, value in (
        ("FUZZBUCKET_FLASK_SECRET_KEY", "shhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"),
        ("FUZZBUCKET_AUTH_PROVIDER", "github-oauth"),
        ("FUZZBUCKET_GITHUB_OAUTH_CLIENT_ID", "abc123"),
        ("FUZZBUCKET_GITHUB_OAUTH_CLIENT_SECRET", "xyz456"),
        ("FUZZBUCKET_OAUTH_AUTH_URL", ""),
        ("FUZZBUCKET_OAUTH_BASE_URL", ""),
        ("FUZZBUCKET_OAUTH_CLIENT_ID", "abc123"),
        ("FUZZBUCKET_OAUTH_CLIENT_SECRET", "xyz456"),
        ("FUZZBUCKET_OAUTH_TOKEN_URL", ""),
        ("FUZZBUCKET_OAUTH_MAX_AGE", "90 days"),
        ("FUZZBUCKET_OAUTH_SCOPE", "openid"),
    ):
        os.environ.setdefault(key, value)


@pytest.fixture
def nowish() -> datetime.datetime:
    return datetime.datetime(2020, 3, 15, 11, 22, 4, 655788)
