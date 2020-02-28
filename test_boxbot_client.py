import argparse
import contextlib
import io
import json

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
    client._setup()
    assert client is not None


def gen_fake_urlopen(response):
    @contextlib.contextmanager
    def fake_urlopen(request):
        yield response

    return fake_urlopen


def test_client_list(monkeypatch):
    client = boxbot_client.Client()
    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(io.StringIO(json.dumps({"boxes": [{"fancy": "probably"}]}))),
    )
    client.list(None)


def test_client_create(monkeypatch):
    client = boxbot_client.Client()
    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(
            io.StringIO(
                json.dumps(
                    {"boxes": [{"public_ip": None, "special": "like all the others"}]}
                )
            )
        ),
    )
    client.create(
        argparse.Namespace(
            instance_type="t8.pico", image_alias="ubuntu49", connect=False
        )
    )


def test_client_delete(monkeypatch):
    client = boxbot_client.Client()
    monkeypatch.setattr(
        client, "_urlopen", gen_fake_urlopen(io.StringIO("")),
    )
    client.delete(argparse.Namespace(instance_id="i-havesomuchmoretogive"))
