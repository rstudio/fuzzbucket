import contextlib
import io
import json
import os

import pytest

import fuzzbucket_client


@pytest.fixture(autouse=True)
def patched_env(tmpdir, monkeypatch):
    fake_home = tmpdir.join("home")
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("FUZZBUCKET_CREDENTIALS", "admin:token")
    monkeypatch.setenv(
        "FUZZBUCKET_URL", "http://fuzzbucket.example.org/bleep/bloop/dev"
    )


def test_client_setup():
    client = fuzzbucket_client.Client()
    client._setup()
    assert client is not None


def gen_fake_urlopen(response):
    @contextlib.contextmanager
    def fake_urlopen(request):
        yield response

    return fake_urlopen


def test_client_list(monkeypatch):
    client = fuzzbucket_client.Client()
    monkeypatch.setattr(fuzzbucket_client, "default_client", lambda: client)
    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(
            io.StringIO(
                json.dumps({"boxes": [{"name": "sparkles", "fancy": "probably"}]})
            )
        ),
    )
    ret = fuzzbucket_client.main(["fuzzbucket-client", "list"])
    assert ret == 0


def test_client_create(monkeypatch):
    client = fuzzbucket_client.Client()
    monkeypatch.setattr(fuzzbucket_client, "default_client", lambda: client)
    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(
            io.StringIO(
                json.dumps(
                    {
                        "boxes": [
                            {
                                "name": "ubuntu49",
                                "public_ip": None,
                                "special": "like all the others",
                            }
                        ]
                    }
                )
            )
        ),
    )
    ret = fuzzbucket_client.main(
        [
            "fuzzbucket-client",
            "create",
            "ubuntu49",
            "--instance-type=t8.pico",
            "--connect",
        ]
    )
    assert ret == 0

    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(
            io.StringIO(
                json.dumps(
                    {
                        "boxes": [
                            {
                                "name": "snowflek",
                                "public_ip": None,
                                "worth": "immeasurable",
                            }
                        ]
                    }
                )
            )
        ),
    )
    ret = fuzzbucket_client.main(
        [
            "fuzzbucket-client",
            "create",
            "ami-fafbafabcadabfabcdabcbaf",
            "--instance-type=t8.nano",
        ]
    )
    assert ret == 0


def test_client_delete(monkeypatch):
    client = fuzzbucket_client.Client()
    monkeypatch.setattr(fuzzbucket_client, "default_client", lambda: client)

    request_counter = {"count": 0}

    def fake_urlopen(req):
        response = [
            io.StringIO(
                json.dumps(
                    {
                        "boxes": [
                            {
                                "name": "welp",
                                "public_ip": None,
                                "instance_id": "i-fafafafafaf",
                                "special": "is this the end",
                            }
                        ]
                    }
                )
            ),
            io.StringIO(""),
        ][request_counter["count"]]
        request_counter["count"] += 1
        return response

    monkeypatch.setattr(client, "_urlopen", fake_urlopen)
    ret = fuzzbucket_client.main(["fuzzbucket-client", "delete", "welp"])
    assert ret == 0


def test_client_reboot(monkeypatch):
    client = fuzzbucket_client.Client()
    monkeypatch.setattr(fuzzbucket_client, "default_client", lambda: client)

    request_counter = {"count": 0}

    def fake_urlopen(req):
        response = [
            io.StringIO(
                json.dumps(
                    {
                        "boxes": [
                            {
                                "name": "zombie-skills",
                                "public_ip": None,
                                "instance_id": "i-fafafafafaf",
                                "brainzzz": "eating",
                            }
                        ]
                    }
                )
            ),
            io.StringIO(""),
        ][request_counter["count"]]
        request_counter["count"] += 1
        return response

    monkeypatch.setattr(client, "_urlopen", fake_urlopen)
    ret = fuzzbucket_client.main(["fuzzbucket-client", "reboot", "zombie-skills"])
    assert ret == 0


def test_client_ssh(monkeypatch):
    client = fuzzbucket_client.Client()
    monkeypatch.setattr(fuzzbucket_client, "default_client", lambda: client)

    def fake_execvp(file, args):
        assert file == "ssh"
        assert args == ["ssh", "ethereal-plane.example.org", "-l", "cornelius"]

    def fake_list_boxes():
        return [{"name": "koolthing", "public_dns_name": "ethereal-plane.example.org"}]

    monkeypatch.setattr(os, "execvp", fake_execvp)
    monkeypatch.setattr(client, "_list_boxes", fake_list_boxes)

    ret = fuzzbucket_client.main(
        ["fuzzbucket-client", "ssh", "koolthing", "-l", "cornelius"]
    )
    assert ret == 0


def test_client_scp(monkeypatch):
    client = fuzzbucket_client.Client()
    monkeypatch.setattr(fuzzbucket_client, "default_client", lambda: client)

    def fake_execvp(file, args):
        assert file == "scp"
        assert args == [
            "scp",
            "-r",
            "cornelius@ethereal-plane.example.org:/var/log/",
            "./local/dump",
        ]

    def fake_list_boxes():
        return [{"name": "koolthing", "public_dns_name": "ethereal-plane.example.org"}]

    monkeypatch.setattr(os, "execvp", fake_execvp)
    monkeypatch.setattr(client, "_list_boxes", fake_list_boxes)

    ret = fuzzbucket_client.main(
        [
            "fuzzbucket-client",
            "scp",
            "koolthing",
            "-r",
            "cornelius@__BOX__:/var/log/",
            "./local/dump",
        ]
    )
    assert ret == 0
