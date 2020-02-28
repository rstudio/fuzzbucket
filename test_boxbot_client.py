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
    monkeypatch.setattr(boxbot_client, "default_client", lambda: client)
    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(io.StringIO(json.dumps({"boxes": [{"fancy": "probably"}]}))),
    )
    boxbot_client.main(["boxbot-client", "list"])


def test_client_create(monkeypatch):
    client = boxbot_client.Client()
    monkeypatch.setattr(boxbot_client, "default_client", lambda: client)
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
    boxbot_client.main(
        ["boxbot-client", "create", "ubuntu49", "--instance-type=t8.pico", "--connect"]
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
    boxbot_client.main(
        [
            "boxbot-client",
            "create",
            "ami-fafbafabcadabfabcdabcbaf",
            "--instance-type=t8.nano",
        ]
    )


def test_client_delete(monkeypatch):
    client = boxbot_client.Client()
    monkeypatch.setattr(boxbot_client, "default_client", lambda: client)
    monkeypatch.setattr(
        client, "_urlopen", gen_fake_urlopen(io.StringIO("")),
    )
    boxbot_client.main(["boxbot-client", "delete", "welp"])


def test_client_reboot(monkeypatch):
    client = boxbot_client.Client()
    monkeypatch.setattr(boxbot_client, "default_client", lambda: client)
    monkeypatch.setattr(
        client, "_urlopen", gen_fake_urlopen(io.StringIO("")),
    )
    boxbot_client.main(["boxbot-client", "reboot", "zombie-skills"])


def test_client_ssh(monkeypatch):
    client = boxbot_client.Client()
    monkeypatch.setattr(boxbot_client, "default_client", lambda: client)

    def fake_execvp(file, args):
        assert file == "ssh"
        assert args == ["ssh", "cornelius@ethereal-plane.example.org"]

    def fake_list_boxes():
        return [{"name": "koolthing", "public_dns_name": "ethereal-plane.example.org"}]

    monkeypatch.setattr(os, "execvp", fake_execvp)
    monkeypatch.setattr(client, "_list_boxes", fake_list_boxes)

    boxbot_client.main(["boxbot-client", "ssh", "koolthing", "--ssh-user=cornelius"])
