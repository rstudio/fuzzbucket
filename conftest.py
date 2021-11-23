import datetime
import os

import pytest


@pytest.fixture(scope="session", autouse=True)
def env_setup():
    for key, value in (
        ("FUZZBUCKET_FLASK_SECRET_KEY", "shhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"),
        ("FUZZBUCKET_GITHUB_OAUTH_CLIENT_ID", "abc123"),
        ("FUZZBUCKET_GITHUB_OAUTH_CLIENT_SECRET", "xyz456"),
        ("FUZZBUCKET_IMAGE_ALIASES_TABLE_NAME", "image-aliases"),
        ("FUZZBUCKET_USERS_TABLE_NAME", "users"),
    ):
        os.environ.setdefault(key, value)


@pytest.fixture
def nowish() -> datetime.datetime:
    return datetime.datetime(2020, 3, 15, 11, 22, 4, 655788)
