import argparse
import contextlib
import io
import json
import os
import re
import subprocess
import urllib.request

import pkg_resources
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


def test_default_client():
    assert fuzzbucket_client.default_client() is not None


@pytest.mark.parametrize(
    "err,git_err,pkg_err,expected",
    [
        pytest.param(False, False, False, "stub+version.number.ok", id="from_git"),
        pytest.param(False, True, False, "stub+version.number.ok", id="from_pkg"),
        pytest.param(False, True, True, fuzzbucket_client.__version__, id="from_var1"),
        pytest.param(True, True, True, fuzzbucket_client.__version__, id="from_var2"),
    ],
)
def test_full_version(monkeypatch, err, git_err, pkg_err, expected):
    def fake_check_output(*_, **__):
        if err:
            raise ValueError("boom")
        if git_err:
            raise subprocess.CalledProcessError(86, ["ugh"])
        return "stub-version-number-ok\n".encode("utf-8")

    class FakeDist:
        def __init__(self, dist):
            self.dist = dist
            self.version = "stub+version.number.ok"

    def fake_get_distribution(dist):
        if pkg_err:
            raise ValueError("ack")
        return FakeDist(dist)

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)
    monkeypatch.setattr(pkg_resources, "get_distribution", fake_get_distribution)
    monkeypatch.setattr(
        fuzzbucket_client, "log_level", lambda: fuzzbucket_client.LOG_LEVEL_DEBUG
    )
    fuzzbucket_client.full_version.cache_clear()
    assert fuzzbucket_client.full_version() == expected


def test_client_setup():
    client = fuzzbucket_client.Client()
    client._setup()
    assert client is not None


def gen_fake_urlopen(response):
    @contextlib.contextmanager
    def fake_urlopen(request):
        yield response

    return fake_urlopen


@pytest.mark.parametrize(
    "errors,log_level,log_match,expected",
    [
        pytest.param((), fuzzbucket_client.DEFAULT_LOG_LEVEL, None, True, id="happy"),
        pytest.param(
            ("setup",),
            fuzzbucket_client.DEFAULT_LOG_LEVEL,
            "command.+failed err=.+setup error",
            False,
            id="setup_err",
        ),
        pytest.param(
            ("method",),
            fuzzbucket_client.DEFAULT_LOG_LEVEL,
            "command.+failed err=.+method error",
            False,
            id="method_err",
        ),
        pytest.param(
            ("http",),
            fuzzbucket_client.DEFAULT_LOG_LEVEL,
            "command.+failed err=.+http error",
            False,
            id="http_err",
        ),
        pytest.param(
            ("http", "json"),
            fuzzbucket_client.DEFAULT_LOG_LEVEL,
            "command.+failed err=.+json error",
            False,
            id="http_json_err",
        ),
    ],
)
def test_command_decorator(monkeypatch, caplog, errors, log_level, log_match, expected):
    class FakeClient:
        def _setup(self):
            if "setup" in errors:
                raise ValueError("setup error")

    def fake_method(self, known_args, unknown_args):
        if "method" in errors:
            raise ValueError("method error")
        if "http" in errors:
            raise urllib.request.HTTPError("http://nope", 599, "ugh", [], None)
        return True

    def fake_load(fp):
        if "json" in errors:
            raise ValueError("json error")
        return {"error": "http error"}

    monkeypatch.setattr(json, "load", fake_load)
    decorated = fuzzbucket_client._command(fake_method)
    assert decorated(FakeClient(), "known", "unknown") == expected
    if log_match is not None:
        assert re.search(log_match, caplog.text) is not None


def test_client_version(capsys):
    ret = fuzzbucket_client.main(["fuzzbucket-client", "--version"])
    assert ret == 0
    captured = capsys.readouterr()
    assert re.match("fuzzbucket-client .+", captured.out) is not None


def test_client_no_func(capsys):
    ret = fuzzbucket_client.main(["fuzzbucket-client"])
    assert ret == 2
    captured = capsys.readouterr()
    for match in (
        "^usage: .+--version.+",
        "^A client for fuzzbucket",
        "^optional arguments:",
        "^subcommands:",
        "^ +delete-alias.+Delete an image alias",
    ):
        assert re.search(match, captured.out, re.MULTILINE) is not None


def test_client_failing_func(monkeypatch, capsys):
    client = fuzzbucket_client.Client()
    monkeypatch.setattr(fuzzbucket_client, "default_client", lambda: client)
    monkeypatch.setattr(client, "list", lambda _, __: False)
    ret = fuzzbucket_client.main(["fuzzbucket-client", "list"])
    assert ret == 86


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


def test_client_delete(monkeypatch, caplog):
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
                            },
                            {
                                "name": "welpington",
                                "public_ip": None,
                                "instance_id": "i-fafafababab",
                            },
                        ]
                    }
                )
            ),
            io.StringIO(""),
            io.StringIO(""),
        ][request_counter["count"]]
        request_counter["count"] += 1
        return response

    monkeypatch.setattr(client, "_urlopen", fake_urlopen)
    ret = fuzzbucket_client.main(["fuzzbucket-client", "delete", "welp*"])
    assert ret == 0

    assert re.search(".*deleted box for.*name=welp$", caplog.text, re.MULTILINE)
    assert re.search(".*deleted box for.*name=welpington$", caplog.text, re.MULTILINE)


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
        assert args == [
            "ssh",
            "ethereal-plane.example.org",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "StrictHostKeyChecking=no",
            "-l",
            "ubuntu",
            "ls",
            "-la",
        ]

    def fake_list_boxes():
        return [{"name": "koolthing", "public_dns_name": "ethereal-plane.example.org"}]

    monkeypatch.setattr(os, "execvp", fake_execvp)
    monkeypatch.setattr(client, "_list_boxes", fake_list_boxes)

    ret = fuzzbucket_client.main(["fuzzbucket-client", "ssh", "koolthing", "ls", "-la"])
    assert ret == 0


def test_client_scp(monkeypatch):
    client = fuzzbucket_client.Client()
    monkeypatch.setattr(fuzzbucket_client, "default_client", lambda: client)

    def fake_execvp(file, args):
        assert file == "scp"
        assert args == [
            "scp",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "StrictHostKeyChecking=no",
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


@pytest.mark.parametrize(
    "api_response,stdout_match,expected",
    [
        pytest.param(
            {"image_aliases": {"chonk": "ami-fafababacaca", "wee": "ami-0a0a0a0a0a"}},
            "(chonk = ami-fafababacaca|wee = ami-0a0a0a0a0a)",
            True,
            id="ok",
        ),
        pytest.param({"error": "oh no"}, None, False, id="err",),
    ],
)
def test_client_list_aliases(monkeypatch, capsys, api_response, stdout_match, expected):
    client = fuzzbucket_client.Client()
    monkeypatch.setattr(fuzzbucket_client, "default_client", lambda: client)

    monkeypatch.setattr(
        client, "_urlopen", gen_fake_urlopen(io.StringIO(json.dumps(api_response))),
    )

    assert client.list_aliases("known", "unknown") == expected
    if stdout_match is not None:
        captured = capsys.readouterr()
        assert re.search(stdout_match, captured.out) is not None


@pytest.mark.parametrize(
    "api_response,stdout_match,expected",
    [
        pytest.param(
            {"image_aliases": {"blep": "ami-babacacafafa"}},
            "blep = ami-babacacafafa",
            True,
            id="ok",
        ),
        pytest.param({"error": "oh no"}, None, False, id="err"),
    ],
)
def test_client_create_alias(monkeypatch, capsys, api_response, stdout_match, expected):
    client = fuzzbucket_client.Client()
    monkeypatch.setattr(fuzzbucket_client, "default_client", lambda: client)

    monkeypatch.setattr(
        client, "_urlopen", gen_fake_urlopen(io.StringIO(json.dumps(api_response))),
    )

    assert (
        client.create_alias(
            argparse.Namespace(alias="blep", ami="ami-babacacafafa"), "unknown"
        )
        == expected
    )
    if stdout_match is not None:
        captured = capsys.readouterr()
        assert re.search(stdout_match, captured.out) is not None


def test_client_delete_alias(monkeypatch, caplog):
    client = fuzzbucket_client.Client()
    monkeypatch.setattr(fuzzbucket_client, "default_client", lambda: client)

    monkeypatch.setattr(client, "_urlopen", gen_fake_urlopen(io.StringIO("")))

    assert client.delete_alias(argparse.Namespace(alias="hurr"), "unknown")
    assert "deleted alias" in caplog.text
