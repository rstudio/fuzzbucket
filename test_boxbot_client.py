import argparse
import contextlib
import io
import json
import os

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
        argparse.Namespace(instance_type="t8.pico", image="ubuntu49", connect=False)
    )

    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(
            io.StringIO(
                json.dumps({"boxes": [{"public_ip": None, "worth": "immeasurable"}]})
            )
        ),
    )
    client.create(
        argparse.Namespace(
            instance_type="t9.nano", image="ami-fafbafabcadabfabcdabcbaf", connect=False
        )
    )


def test_client_delete(monkeypatch):
    client = boxbot_client.Client()
    monkeypatch.setattr(
        client, "_urlopen", gen_fake_urlopen(io.StringIO("")),
    )
    client.delete(argparse.Namespace(instance_id="i-havesomuchmoretogive"))


def test_client_ssh(monkeypatch):
    client = boxbot_client.Client()

    def fake_execvp(file, args):
        assert file == "ssh"
        assert args == ["ssh", "cornelius@ethereal-plane.example.org"]

    def fake_list_boxes():
        return [{"name": "koolthing", "public_dns_name": "ethereal-plane.example.org"}]

    monkeypatch.setattr(os, "execvp", fake_execvp)
    monkeypatch.setattr(client, "_list_boxes", fake_list_boxes)

    client.ssh(argparse.Namespace(box="koolthing", ssh_user="cornelius"))
