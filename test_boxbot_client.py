import pytest

import boxbot_client


@pytest.fixture(autouse=True)
def patched_env(tmpdir, monkeypatch):
    fake_home = tmpdir.join("home")
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("BOXBOT_CREDENTIALS", "admin:token")
    monkeypatch.setenv("BOXBOT_URL", "http://boxbot.example.org/bleep/bloop/dev")


def test_client_setup():
    client = boxbot_client.Client()
    client.setup()
