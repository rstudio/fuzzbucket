import argparse
import contextlib
import datetime
import email
import io
import json
import logging
import os
import random
import re
import urllib.request
import urllib.response

import pytest

import fuzzbucket_client.__main__


@pytest.fixture
def nowish() -> datetime.datetime:
    return datetime.datetime(2020, 3, 15, 11, 22, 4, 655788)


class FakePath:
    def __init__(self, filepath: str):
        self._orig_filepath = filepath
        self.text_content = ""

    @property
    def name(self):
        return os.path.basename(self._orig_filepath)

    def read_text(self):
        if self.text_content is None:
            raise IOError("oh no")
        return self.text_content


@pytest.fixture(autouse=True)
def config_setup(tmpdir, monkeypatch):
    url = f"http://fuzzbucket.example.org/bleep/bloop/dev/{random.randint(42, 666)}"
    fake_home = tmpdir.join("home")
    cache_fuzzbucket_dir = fake_home.mkdir().mkdir(".cache").mkdir("fuzzbucket")
    cache_fuzzbucket_dir.join("credentials").write_text(
        f'[server "{url}"]\ncredentials = whimsy:doodles\n', "utf-8"
    )
    cache_fuzzbucket_dir.join("preferences").write_text(
        json.dumps({"default_key_alias": "lovely", "//": "WARNING: omgosh donut edit"}),
        "utf-8",
    )
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("FUZZBUCKET_URL", url)
    os.environ.pop("FUZZBUCKET_CREDENTIALS", None)


def test_trinary_behavior():
    assert str(fuzzbucket_client.__main__._TrinaryBehavior.ALWAYS) == "always"

    with pytest.raises(ValueError):
        fuzzbucket_client.__main__._TrinaryBehavior("boguster")


def test_default_client():
    assert fuzzbucket_client.__main__.default_client() is not None


def test_client_setup():
    client = fuzzbucket_client.__main__.Client()
    client._setup()
    assert client is not None

    client._env.pop("FUZZBUCKET_URL")
    with pytest.raises(ValueError):
        client._setup()

    client._env["FUZZBUCKET_URL"] = "not none"
    client._cached_credentials = None
    os.remove(client._credentials_file)
    with pytest.raises(ValueError):
        client._setup()


def gen_fake_urlopen(response, http_exc=None, empty_methods=(), request_hook=None):
    @contextlib.contextmanager
    def fake_urlopen(request):
        if request_hook is not None:
            request_hook(request)
        if request.get_method() in empty_methods:
            yield io.BytesIO()
            return
        if http_exc is not None:
            raise urllib.request.HTTPError(*(list(http_exc) + [response]))
        yield response

    return fake_urlopen


@pytest.mark.parametrize(
    ("errors", "log_level", "log_matches", "out_matches", "expected"),
    [
        pytest.param((), logging.INFO, (), (), True, id="happy"),
        pytest.param(
            ("setup",),
            logging.INFO,
            ("command.+failed err=.+setup error",),
            (),
            False,
            id="setup_err",
        ),
        pytest.param(
            ("setup_auth",),
            logging.INFO,
            (
                "command.+failed err=No credentials found for "
                + "url='http://nope' in file='/some/hecking/place'",
            ),
            (
                "^Please run the following command",
                "to grant access to Fuzzbucket",
                "fuzzbucket-client login",
            ),
            False,
            id="setup_auth_err",
        ),
        pytest.param(
            ("method",),
            logging.INFO,
            ("command.+failed err=.+method error",),
            (),
            False,
            id="method_err",
        ),
        pytest.param(
            ("http",),
            logging.INFO,
            ("command.+failed err=.+http error",),
            (),
            False,
            id="http_err",
        ),
        pytest.param(
            ("http_auth",),
            logging.INFO,
            ("command.+failed err=.+http_auth error",),
            (
                "^Please run the following command",
                "to grant access to Fuzzbucket",
                "fuzzbucket-client login",
            ),
            False,
            id="http_auth_err",
        ),
        pytest.param(
            ("http", "json"),
            logging.INFO,
            ("command.+failed err=.+json error",),
            (),
            False,
            id="http_json_err",
        ),
        pytest.param(
            ("http", "json"),
            logging.DEBUG,
            (
                "command.+failed",
                "Traceback \\(most recent call last\\):",
                "ValueError: json error",
            ),
            (),
            False,
            id="http_json_err",
        ),
    ],
)
def test_command_decorator(
    monkeypatch, caplog, capsys, errors, log_level, log_matches, out_matches, expected
):
    class FakeClient:
        def _setup(self):
            if "setup_auth" in errors:
                raise fuzzbucket_client.__main__.CredentialsError(
                    "http://nope", "/some/hecking/place"
                )
            if "setup" in errors:
                raise ValueError("setup error")

        def _finalize(self):
            if "finalize" in errors:
                raise ValueError("finalize error")

    def fake_method(*_):
        if "method" in errors:
            raise ValueError("method error")
        if "http" in errors:
            raise urllib.request.HTTPError(
                "http://nope",
                599,
                "ugh",
                [],  # type: ignore
                None,
            )
        if "http_auth" in errors:
            raise urllib.request.HTTPError(
                "http://nope",
                403,
                "no",
                [],  # type: ignore
                None,
            )
        return True

    def fake_load(_):
        if "json" in errors:
            raise ValueError("json error")
        if "http_auth" in errors:
            return {"error": "http_auth error"}
        return {"error": "http error"}

    caplog.set_level(log_level)
    monkeypatch.setattr(fuzzbucket_client.__main__, "log_level", lambda: log_level)
    monkeypatch.setattr(json, "load", fake_load)
    decorated = fuzzbucket_client.__main__._command(fake_method)
    assert decorated(FakeClient(), "known", "unknown") == expected
    for log_match in log_matches:
        assert re.search(log_match, caplog.text) is not None
    captured = capsys.readouterr()
    for out_match in out_matches:
        assert re.search(out_match, captured.out, re.MULTILINE) is not None


def test_client_version(capsys):
    ret = fuzzbucket_client.__main__.main(["fuzzbucket-client", "--version"])
    assert ret == 0
    captured = capsys.readouterr()
    assert re.match("fuzzbucket-client .+", captured.out) is not None


@pytest.mark.parametrize(
    ("args", "expected_lines"),
    [
        pytest.param(
            ["4 weeks, 3 days"],
            ["[ttl]", "str = 31 days, 0:00:00", "float = 2678400.0"],
            id="ini",
        ),
        pytest.param(
            ["9 weeks, 5 days", "-j"],
            [
                "{",
                '  "ttl": {',
                '    "str": "68 days, 0:00:00",',
                '    "float": "5875200.0"',
                "  }",
                "}",
            ],
            id="json",
        ),
    ],
)
def test_client_check_ttl(capsys, args, expected_lines):
    ret = fuzzbucket_client.__main__.main(["fuzzbucket-client", "--check-ttl"] + args)
    assert ret == 0
    captured = capsys.readouterr()
    assert expected_lines == captured.out.strip().splitlines()


def test_client_no_func(capsys):
    ret = fuzzbucket_client.__main__.main(["fuzzbucket-client"])
    assert ret == 2
    captured = capsys.readouterr()
    for match in (
        "^usage: .+--version.+",
        "^A client for fuzzbucket",
        "^option(al argument|)s:",
        "^ +delete-alias.+delete an image alias",
    ):
        assert re.search(match, captured.out, re.MULTILINE) is not None, (
            "usage does not match " + match
        )


def test_client_failing_func(monkeypatch):
    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)
    monkeypatch.setattr(client, "ls", lambda _, __: False)
    ret = fuzzbucket_client.__main__.main(["fuzzbucket-client", "ls"])
    assert ret == 86


@pytest.mark.parametrize(
    ("args", "returning"),
    [
        pytest.param(("ls",), 0, id="empty"),
        pytest.param(("-j", "list"), 0, id="output_json"),
        pytest.param(("list", "spark*"), 0, id="matching"),
        pytest.param(("list", "*giraffes*"), 86, id="not_matching"),
    ],
)
def test_client_ls(monkeypatch, args, returning):
    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)
    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(
            io.BytesIO(
                json.dumps(
                    {"boxes": [{"name": "sparkles", "fancy": "probably"}]}
                ).encode()
            )
        ),
    )
    ret = fuzzbucket_client.__main__.main(["fuzzbucket-client"] + list(args))
    assert ret == returning


@pytest.mark.parametrize(
    ("cmd_args", "secrets", "url", "raises", "written", "expected"),
    [
        pytest.param(
            ("bugs",),
            ("wonketywoopwoopwoopwoopwoopwoopwoopwoopwoo",),
            "http://sure.example.org",
            False,
            ("bugs", "wonketywoopwoopwoopwoopwoopwoopwoopwoopwoo"),
            0,
            id="happy",
        ),
        pytest.param(
            ("daffy", "--name", "matzo"),
            ("despicable................................",),
            "http://sure.example.org",
            False,
            ("daffy", "despicable................................"),
            0,
            id="happy_named",
        ),
        pytest.param(
            ("elmer",),
            (":typing:", "9ccb489abe5c900316fd57482b23c38bb99c727900"),
            "https://vewwyquiet.jobs",
            False,
            ("elmer", "9ccb489abe5c900316fd57482b23c38bb99c727900"),
            0,
            id="eventually_happy",
        ),
        pytest.param(
            ("wylie",),
            ("femmeroadrunner???",),
            "https://shop.acme.com",
            True,
            (),
            86,
            id="interrupted",
        ),
        pytest.param(
            ("speedy",),
            ("I am more than a stereotype",),
            None,
            False,
            (),
            86,
            id="no_url",
        ),
    ],
)
def test_client_login(
    monkeypatch, capsys, cmd_args, secrets, url, raises, written, expected
):
    state: dict[str, str | int | None] = {"secret_count": 0}

    def fake_write_credentials(user, secret, name=None):
        state.update(user=user, secret=secret, name=name)

    def fake_getpass(prompt):
        state.update(prompt=prompt)
        ret = secrets[state["secret_count"]]
        state["secret_count"] += 1  # type: ignore
        if raises:
            raise KeyboardInterrupt("control this")
        return ret

    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)
    monkeypatch.setattr(fuzzbucket_client.__main__.webbrowser, "open", lambda _: None)
    monkeypatch.setattr(fuzzbucket_client.__main__.getpass, "getpass", fake_getpass)
    monkeypatch.setattr(client, "_write_credentials", fake_write_credentials)
    client._env["FUZZBUCKET_URL"] = url

    ret = fuzzbucket_client.__main__.main(
        ["fuzzbucket-client", "login"] + list(cmd_args)
    )

    assert ret == expected
    captured = capsys.readouterr()
    if url is not None:
        assert "Attempting to open the following URL" in captured.out
    if len(secrets) > 1:
        assert "Invalid secret provided" in captured.out
    if raises or url is None:
        return
    assert (state.get("user"), state.get("secret")) == written
    assert "Login successful" in captured.out


def test_client_logout(monkeypatch):
    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)
    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(io.BytesIO()),
    )
    ret = fuzzbucket_client.__main__.main(["fuzzbucket-client", "logout"])
    assert ret == 0


@pytest.mark.parametrize(
    ("api_response", "http_exc", "cmd_args", "log_matches", "expected"),
    [
        pytest.param(
            {
                "boxes": [
                    {
                        "name": "ubuntu49",
                        "public_ip": None,
                        "special": "like all the others",
                    }
                ]
            },
            None,
            (
                "ubuntu49",
                "--connect",
            ),
            ("created box for user=.+",),
            0,
            id="happy_alias",
        ),
        pytest.param(
            {
                "boxes": [
                    {
                        "name": "ubuntu49",
                        "public_ip": None,
                        "special": "like all the others",
                    }
                ]
            },
            None,
            (
                "ubuntu49",
                "--root-volume-size",
                "11",
            ),
            ("created box for user=.+",),
            0,
            id="happy_with_root_volume_size",
        ),
        pytest.param(
            {
                "boxes": [
                    {
                        "name": "ubuntu49",
                        "public_ip": None,
                        "special": "like all the others",
                    }
                ]
            },
            None,
            (
                "ubuntu49",
                "--root-volume-size",
                "puppies",
            ),
            ("root_volume_size=[\"']puppies[\"'] is not numeric",),
            86,
            id="bad_root_volume_size",
        ),
        pytest.param(
            {
                "boxes": [
                    {"name": "snowflek", "public_ip": None, "worth": "immeasurable"}
                ]
            },
            None,
            ("ami-fafbafabcadabfabcdabcbaf", "--instance-type=t8.nano"),
            ("created box for user=.+",),
            0,
            id="happy_ami",
        ),
        pytest.param(
            {
                "boxes": [
                    {"name": "snowflek", "public_ip": None, "worth": "immeasurable"}
                ]
            },
            None,
            (
                "ubuntu49",
                "--instance-tags=friend:true,heart-eyes:cat",
            ),
            ("created box for user=.+",),
            0,
            id="happy_instance_tags",
        ),
        pytest.param(
            {
                "boxes": [
                    {"name": "snowflek", "public_ip": None, "worth": "immeasurable"}
                ]
            },
            None,
            (
                "ubuntu49",
                "--instance-tags=,heart%3Aeyes:cat,wat:",
            ),
            ("created box for user=.+",),
            0,
            id="weird_instance_tags",
        ),
        pytest.param(
            {
                "boxes": [
                    {
                        "name": "ubuntu49",
                        "public_ip": "256.256.0.-1",
                        "special": "like the one before",
                    }
                ]
            },
            (
                "http://fake",
                409,
                "you already did this",
                [("Content-Type", "application/json")],
            ),
            (
                "ubuntu49",
                "--instance-type=t8.pico",
                "--connect",
            ),
            ("matching box already exists",),
            0,
            id="repeat_alias",
        ),
        pytest.param(
            {"error": "not today"},
            (
                "http://fake",
                500,
                "just cannot",
                [("Content-Type", "application/json")],
            ),
            (
                "ubuntu49",
                "--instance-type=t8.pico",
                "--connect",
            ),
            ("command [\"']create[\"'] failed",),
            86,
            id="api_err",
        ),
        pytest.param(
            {},
            (),
            (
                "ubuntu49",
                "--instance-type=t8.pico",
                "--ttl",
                "42",
            ),
            ("ttl=.+ is below the minimum.+",),
            86,
            id="low_ttl",
        ),
        pytest.param(
            {},
            (),
            (
                "ubuntu49",
                "--instance-type=t8.pico",
                "--ttl",
                "42 weeks",
            ),
            ("ttl=.+ is above the maximum.+",),
            86,
            id="high_ttl",
        ),
    ],
)
def test_client_create(
    monkeypatch, caplog, api_response, http_exc, cmd_args, log_matches, expected
):
    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)
    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(
            io.BytesIO(json.dumps(api_response).encode()), http_exc=http_exc
        ),
    )
    ret = fuzzbucket_client.__main__.main(
        ["fuzzbucket-client", "create"] + list(cmd_args)
    )
    assert ret == expected
    for log_match in log_matches:
        assert re.search(log_match, caplog.text) is not None


@pytest.mark.parametrize(
    (
        "api_response",
        "http_exc",
        "cmd_args",
        "log_matches",
        "expected",
        "expected_request",
    ),
    [
        pytest.param(
            {
                "boxes": [
                    {
                        "age": "0:13:12",
                        "created_at": 1584282124.655788,
                        "instance_id": "i-fafafafafaf",
                        "name": "ubuntu49",
                        "public_ip": "256.256.256.256",
                    },
                ]
            },
            None,
            (
                "ubuntu49",
                "--ttl",
                "5 days, 6 hours, 37 minutes, 11 seconds",
                "--instance-tags",
                "scutum:scorpius,castle:keys,wat:",
            ),
            ("updated box for user=.+",),
            0,
            dict(
                instance_tags=dict(scutum="scorpius", castle="keys", wat=""),
                ttl="456623",
            ),
            id="happy",
        ),
        pytest.param(
            {
                "boxes": [
                    {
                        "age": "0:13:12",
                        "created_at": 1584282124.655788,
                        "instance_id": "i-fafafafafaf",
                        "name": "ubuntu49",
                        "public_ip": "256.256.256.256",
                    },
                ]
            },
            None,
            (
                "ubuntu49",
                "--instance-tags",
                "scutum:scorpius,castle:keys,wat:",
            ),
            ("updated box for user=.+",),
            0,
            None,
            id="happy_tags_only",
        ),
        pytest.param(
            {},
            None,
            (
                "ubuntu49",
                "--ttl",
                "what is this",
            ),
            (),
            2,
            None,
            id="bad_ttl",
        ),
        pytest.param(
            {},
            None,
            (
                "ubuntu49",
                "--ttl",
                "12 parsecs",
            ),
            (),
            2,
            None,
            id="worse_ttl",
        ),
        pytest.param(
            {
                "boxes": [
                    {
                        "age": "0:13:12",
                        "created_at": 1584282124.655788,
                        "instance_id": "i-fafafafafaf",
                        "name": "ubuntu49",
                        "public_ip": "256.256.256.256",
                    },
                ]
            },
            None,
            (
                "ubuntu49",
                "--ttl",
                "42",
            ),
            ("ttl=.+ is below the minimum.+",),
            86,
            None,
            id="low_ttl",
        ),
        pytest.param(
            {
                "boxes": [
                    {
                        "age": "0:13:12",
                        "created_at": 1584282124.655788,
                        "instance_id": "i-fafafafafaf",
                        "name": "ubuntu49",
                        "public_ip": "256.256.256.256",
                    },
                ]
            },
            None,
            (
                "ubuntu49",
                "--ttl",
                "42 weeks",
            ),
            ("ttl=.+ is above the maximum.+",),
            86,
            None,
            id="high_ttl",
        ),
        pytest.param(
            {
                "boxes": [
                    {
                        "age": "0:13:12",
                        "created_at": 1584282124.655788,
                        "instance_id": "i-fafafafafaf",
                        "name": "ubuntu49",
                        "public_ip": "256.256.256.256",
                    },
                ]
            },
            None,
            ("ubuntu49",),
            ("no updates specified for .+",),
            86,
            None,
            id="no_updates",
        ),
        pytest.param(
            {"boxes": []},
            None,
            ("ubuntu49",),
            ("no boxes found matching .+",),
            86,
            None,
            id="no_match",
        ),
    ],
)
def test_client_update(
    monkeypatch,
    caplog,
    api_response,
    http_exc,
    cmd_args,
    log_matches,
    expected,
    expected_request,
    nowish,
):
    client = fuzzbucket_client.__main__.Client()

    sys_exit_state = {"status": None}

    def capture_sys_exit(status):
        sys_exit_state["status"] = status

    request_state = {}

    def request_hook(request):
        request_state.update(request=request)

    monkeypatch.setattr(
        fuzzbucket_client.__main__,
        "utcnow",
        lambda: nowish,
    )
    monkeypatch.setattr(argparse._sys, "exit", capture_sys_exit)  # type: ignore
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)
    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(
            io.BytesIO(json.dumps(api_response).encode()),
            http_exc=http_exc,
            request_hook=request_hook,
        ),
    )
    ret = fuzzbucket_client.__main__.main(
        ["fuzzbucket-client", "update"] + list(cmd_args)
    )
    if sys_exit_state["status"] is not None:
        assert sys_exit_state["status"] == expected
    else:
        assert ret == expected
    for log_match in log_matches:
        assert re.search(log_match, caplog.text) is not None

    if expected_request is None:
        return

    assert expected_request == json.loads(request_state["request"].data)


@pytest.mark.parametrize(
    ("api_response", "http_exc", "cmd_args", "log_matches", "expected"),
    [
        pytest.param(
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
            },
            None,
            ("welp*",),
            ("deleted box for.+name=welp$", "deleted box for.+name=welpington$"),
            0,
            id="happy",
        ),
        pytest.param(
            {"boxes": []},
            None,
            ("welp*",),
            ("no boxes found matching [\"']welp\\*[\"']",),
            86,
            id="no_match",
        ),
    ],
)
def test_client_delete(
    monkeypatch, caplog, api_response, http_exc, cmd_args, log_matches, expected
):
    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)

    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(
            io.BytesIO(json.dumps(api_response).encode()),
            http_exc=http_exc,
            empty_methods=("DELETE",),
        ),
    )
    ret = fuzzbucket_client.__main__.main(
        ["fuzzbucket-client", "delete"] + list(cmd_args)
    )
    assert ret == expected
    for log_match in log_matches:
        assert re.search(log_match, caplog.text, re.MULTILINE)


@pytest.mark.parametrize(
    ("api_response", "http_exc", "cmd_args", "log_matches", "expected"),
    [
        pytest.param(
            {
                "boxes": [
                    {
                        "name": "zombie-skills",
                        "public_ip": None,
                        "instance_id": "i-fafafafafaf",
                        "brainzzz": "eating",
                    }
                ]
            },
            None,
            ("zombie-skills",),
            ("rebooted box for user=.+ box=[\"']zombie-skills[\"']",),
            0,
            id="happy",
        ),
        pytest.param(
            {"boxes": []},
            None,
            ("nessie",),
            ("no box found matching [\"']nessie[\"']",),
            86,
            id="no_match",
        ),
        pytest.param(
            {"error": "ker-splatz"},
            ("http://nah", 586, "owwie", []),
            ("whoopie-pie",),
            ("command [\"']reboot[\"'] failed err=[\"']ker-splatz[\"']",),
            86,
            id="api_err",
        ),
    ],
)
def test_client_reboot(
    monkeypatch, caplog, api_response, http_exc, cmd_args, log_matches, expected
):
    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)

    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(
            io.BytesIO(json.dumps(api_response).encode()),
            http_exc=http_exc,
            empty_methods=("POST",),
        ),
    )
    ret = fuzzbucket_client.__main__.main(
        ["fuzzbucket-client", "reboot"] + list(cmd_args)
    )
    assert ret == expected
    for log_match in log_matches:
        assert re.search(log_match, caplog.text, re.MULTILINE)


def test_client_ssh(monkeypatch):
    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)

    state = {}

    def fake_execvp(file, args):
        state.update(file=file, args=args)

    def fake_list_boxes():
        return [
            {
                "name": "koolthing",
                "public_dns_name": "ethereal-plane.example.org",
                "instance_id": "i-dadb0dcafebaba",
                "region": "mp-south-2",
            }
        ]

    monkeypatch.setattr(os, "execvp", fake_execvp)
    monkeypatch.setattr(client, "_list_boxes", fake_list_boxes)

    ret = fuzzbucket_client.__main__.main(
        ["fuzzbucket-client", "ssh", "koolthing", "ls", "-la"]
    )
    assert ret == 0

    assert state["file"] == "ssh"
    assert state["args"] == [
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

    state = {}

    def fake_execvp_with_ssm(file, args):
        state.update(file=file, args=args)

    monkeypatch.setattr(os, "execvp", fake_execvp_with_ssm)

    ret = fuzzbucket_client.__main__.main(
        ["fuzzbucket-client", "ssh", "--ssm=always", "koolthing", "ls", "-la"]
    )
    assert ret == 0

    assert state["file"] == "ssh"
    assert state["args"] == [
        "ssh",
        "i-dadb0dcafebaba",
        "-o",
        "ProxyCommand=sh -c 'aws ssm start-session --target i-dadb0dcafebaba "
        + "--region mp-south-2 --document-name AWS-StartSSHSession "
        + "--parameters portNumber=%p'",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "StrictHostKeyChecking=no",
        "-l",
        "ubuntu",
        "ls",
        "-la",
    ]


def test_client_scp(monkeypatch):
    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)

    state = {}

    def fake_execvp(file, args):
        state.update(file=file, args=args)

    def fake_list_boxes():
        return [
            {
                "name": "koolthing",
                "public_dns_name": "ethereal-plane.example.org",
                "instance_id": "i-feedfacecafebeef",
                "region": "mp-south-2",
            }
        ]

    monkeypatch.setattr(os, "execvp", fake_execvp)
    monkeypatch.setattr(client, "_list_boxes", fake_list_boxes)

    ret = fuzzbucket_client.__main__.main(
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

    assert state["file"] == "scp"
    assert state["args"] == [
        "scp",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "StrictHostKeyChecking=no",
        "-r",
        "cornelius@ethereal-plane.example.org:/var/log/",
        "./local/dump",
    ]

    state = {}

    def fake_execvp_with_ssm(file, args):
        state.update(file=file, args=args)

    monkeypatch.setattr(os, "execvp", fake_execvp_with_ssm)

    ret = fuzzbucket_client.__main__.main(
        [
            "fuzzbucket-client",
            "scp",
            "--ssm=always",
            "koolthing",
            "-r",
            "cornelius@__BOX__:/var/log/",
            "./local/dump",
        ]
    )
    assert ret == 0

    assert state["file"] == "scp"
    assert state["args"] == [
        "scp",
        "-o",
        "ProxyCommand=sh -c 'aws ssm start-session --target i-feedfacecafebeef "
        + "--region mp-south-2 --document-name AWS-StartSSHSession "
        + "--parameters portNumber=%p'",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "StrictHostKeyChecking=no",
        "-r",
        "cornelius@i-feedfacecafebeef:/var/log/",
        "./local/dump",
    ]


@pytest.mark.parametrize(
    ("api_response", "data_format", "stdout_match", "expected"),
    [
        pytest.param(
            {"image_aliases": {"chonk": "ami-fafababacaca", "wee": "ami-0a0a0a0a0a"}},
            fuzzbucket_client.__main__._DataFormats.INI,
            "(chonk = ami-fafababacaca|wee = ami-0a0a0a0a0a)",
            True,
            id="ok",
        ),
        pytest.param(
            {"image_aliases": {"chonk": "ami-fafababacaca", "wee": "ami-0a0a0a0a0a"}},
            fuzzbucket_client.__main__._DataFormats.JSON,
            '("chonk": "ami-fafababacaca"|"wee": "ami-0a0a0a0a0a")',
            True,
            id="ok",
        ),
        pytest.param(
            {"error": "oh no"},
            fuzzbucket_client.__main__._DataFormats.INI,
            None,
            False,
            id="err",
        ),
    ],
)
def test_client_list_aliases(
    monkeypatch, capsys, api_response, data_format, stdout_match, expected
):
    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)

    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(io.BytesIO(json.dumps(api_response).encode())),
    )
    client.data_format = data_format

    assert client.list_aliases("known", "unknown") == expected
    if stdout_match is not None:
        captured = capsys.readouterr()
        assert re.search(stdout_match, captured.out) is not None


@pytest.mark.parametrize(
    ("api_response", "data_format", "stdout_match", "expected"),
    [
        pytest.param(
            {"image_aliases": {"blep": "ami-babacacafafa"}},
            fuzzbucket_client.__main__._DataFormats.INI,
            "blep = ami-babacacafafa",
            True,
            id="ok",
        ),
        pytest.param(
            {"image_aliases": {"blep": "ami-babacacafafa"}},
            fuzzbucket_client.__main__._DataFormats.JSON,
            '"blep": "ami-babacacafafa"',
            True,
            id="ok",
        ),
        pytest.param(
            {"error": "oh no"},
            fuzzbucket_client.__main__._DataFormats.INI,
            None,
            False,
            id="err",
        ),
    ],
)
def test_client_create_alias(
    monkeypatch, capsys, api_response, data_format, stdout_match, expected
):
    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)

    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(io.BytesIO(json.dumps(api_response).encode())),
    )
    client.data_format = data_format

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
    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)

    monkeypatch.setattr(client, "_urlopen", gen_fake_urlopen(io.BytesIO()))

    assert client.delete_alias(argparse.Namespace(alias="hurr"), "unknown")
    assert "deleted alias" in caplog.text


@pytest.mark.parametrize(
    ("data_format", "matches"),
    [
        pytest.param(
            fuzzbucket_client.__main__._DataFormats.INI,
            ["any = fields", "allowed = True"],
            id="happy_ini",
        ),
        pytest.param(
            fuzzbucket_client.__main__._DataFormats.JSON,
            ['"any": "fields"', '"allowed": true'],
            id="happy_json",
        ),
    ],
)
def test_client_get_key(monkeypatch, capsys, data_format, matches):
    client = fuzzbucket_client.__main__.Client()
    client.data_format = data_format
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)

    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(io.BytesIO(b'{"key":{"any":"fields","allowed":true}}')),
    )

    assert client.get_key(argparse.Namespace(alias="hurr"), "unknown")

    captured = capsys.readouterr()
    for match in matches:
        assert match in captured.out


def test_client_set_key():
    client = fuzzbucket_client.__main__.Client()
    client._preferences[
        fuzzbucket_client.__main__._Preferences.DEFAULT_KEY_ALIAS.value
    ] = "no"
    assert client.set_key(argparse.Namespace(alias="horses"), "unknown")
    assert (
        client._preferences[
            fuzzbucket_client.__main__._Preferences.DEFAULT_KEY_ALIAS.value
        ]
        == "horses"
    )


@pytest.mark.parametrize(
    ("data_format", "matches"),
    [
        pytest.param(
            fuzzbucket_client.__main__._DataFormats.INI,
            ["braking = litho", "retrograde = True"],
            id="happy_ini",
        ),
        pytest.param(
            fuzzbucket_client.__main__._DataFormats.JSON,
            ['"braking": "litho"', '"retrograde": true'],
            id="happy_json",
        ),
    ],
)
def test_client_list_keys(monkeypatch, capsys, data_format, matches):
    client = fuzzbucket_client.__main__.Client()
    client.data_format = data_format
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)

    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(
            io.BytesIO(b'{"keys":[{"braking":"litho","retrograde":true}]}')
        ),
    )

    assert client.list_keys(argparse.Namespace(), "unknown")

    captured = capsys.readouterr()
    for match in matches:
        assert match in captured.out


@pytest.mark.parametrize(
    ("alias", "filename", "key_material", "success"),
    [
        pytest.param(
            "hurr",
            FakePath("/dev/null"),
            "ssh-rsa tada",
            True,
            id="happy_alias",
        ),
        pytest.param(
            None,
            FakePath("/dev/null/fancy_rsa.pub"),
            "ssh-rsa confetti",
            True,
            id="happy_filename",
        ),
        pytest.param(
            None,
            FakePath("/dev/null/glamorous_ed25519.pub"),
            "ssh-ed25519 watermelons",
            True,
            id="happy_filename_also",
        ),
        pytest.param(
            None,
            FakePath("/dev/null/id_rsa.pub"),
            "ssh-rsa cow2",
            True,
            id="happy_filename_default_alias",
        ),
        pytest.param(
            None,
            FakePath("/dev/null/id_ed25519.pub"),
            "ssh-ed25519 cow2",
            True,
            id="happy_filename_default_alias_also",
        ),
        pytest.param(
            None,
            FakePath("/dev/null/empty_rsa.pub"),
            None,
            False,
            id="failed_file_read",
        ),
    ],
)
def test_client_add_key(monkeypatch, caplog, alias, filename, key_material, success):
    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)

    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(io.BytesIO(b'{"key":{"braking":"litho","retrograde":true}}')),
    )

    filename.text_content = key_material

    assert success == client.add_key(
        argparse.Namespace(alias=alias, filename=filename), "unknown"
    )


def test_client_delete_key(monkeypatch, caplog):
    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)

    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(io.BytesIO(b'{"key":{"braking":"litho","retrograde":true}}')),
    )

    assert client.delete_key(argparse.Namespace(alias="hurr"), "unknown")
    assert "deleted key" in caplog.text


@pytest.mark.parametrize(
    ("args", "response", "out_match", "returning"),
    [
        pytest.param(("whoami",), b'{"you":"castleface"}', "castleface", 0),
        pytest.param(("-j", "whoami"), b'{"you":"castleface"}', "castleface", 0),
        pytest.param(("whoami",), b"{}", None, 86),
    ],
)
def test_client_whoami(args, response, out_match, returning, monkeypatch, capsys):
    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)

    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(io.BytesIO(response)),
    )

    ret = fuzzbucket_client.__main__.main(["fuzzbucket-client"] + list(args))
    assert ret == returning

    if out_match is not None:
        assert out_match in capsys.readouterr().out


@pytest.mark.parametrize(
    ("args", "response", "http_exc", "out_match", "returning"),
    [
        pytest.param(
            ("api", "foul/form"),
            b'{"funeral":"solution"}',
            None,
            '{"funeral":"solution"}',
            0,
            id="simple",
        ),
        pytest.param(
            ("-j", "api", "foul/form"),
            b"<solution>funeral</solution>",
            None,
            "<solution>funeral</solution>",
            0,
            id="ignored_json_format",
        ),
        pytest.param(
            ("api", "-H", "Spicy: 11", "-i", "foul/form"),
            b'{"funeral":"solution"}',
            None,
            'Bear: Foz\n\n{"funeral":"solution"}',
            0,
            id="headers_time",
        ),
        pytest.param(
            ("api", "frock/block"),
            b"perm act\n",
            (
                "http://fakety.example.org/fake",
                418,
                b'{"hecking":"toot"}',
                [("Content-Type", "application/json")],
            ),
            None,
            86,
            id="teapot",
        ),
    ],
)
def test_client_api(
    args,
    response,
    http_exc,
    out_match,
    returning,
    monkeypatch,
    capsys,
):
    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(fuzzbucket_client.__main__, "default_client", lambda: client)

    monkeypatch.setattr(
        client,
        "_urlopen",
        gen_fake_urlopen(
            urllib.response.addinfourl(
                io.BytesIO(response),
                email.message_from_string("Bear: Foz\n"),
                "http://ok.bears.example.org",
            ),
            http_exc=http_exc,
        ),
    )

    ret = fuzzbucket_client.__main__.main(["fuzzbucket-client"] + list(args))
    assert ret == returning

    if out_match is not None:
        assert out_match in capsys.readouterr().out


@pytest.mark.parametrize(
    (
        "env_credentials",
        "user",
        "secret",
        "name",
        "file_exists",
        "file_content",
        "write_matches",
    ),
    [
        pytest.param(
            None,
            "daffy",
            "woohoo",
            None,
            True,
            '[server "http://weau"]\ncredentials = daffy:bugsdrools\n',
            ("^credentials = daffy:woohoo", "^credentials = daffy:bugsdrools"),
            id="existing",
        ),
        pytest.param(
            None,
            "sam",
            "varmint",
            None,
            True,
            "",
            ("^credentials = sam:varmint",),
            id="existing_empty",
        ),
        pytest.param(
            None,
            "foghorn",
            "wellahseenow",
            None,
            False,
            "",
            ("^credentials = foghorn:wellahseenow",),
            id="new_config",
        ),
        pytest.param(
            None,
            "foghorn",
            "wellahseenow",
            "barnyard",
            False,
            "",
            ("^credentials = foghorn:wellahseenow", "^name = barnyard"),
            id="new_config_named",
        ),
        pytest.param(
            "taz:cBJle+yte59ss/jNu+BL",
            None,
            None,
            None,
            False,
            "",
            (),
            id="env_bypass",
        ),
    ],
)
def test_client__write_credentials(
    monkeypatch,
    env_credentials,
    user,
    secret,
    name,
    file_exists,
    file_content,
    write_matches,
):
    state = {"out": io.StringIO()}

    class FakeFile:
        def exists(self):
            return file_exists

        @contextlib.contextmanager
        def open(self, mode: str = "r"):
            assert mode in ("r", "w")
            if mode == "r":
                yield io.StringIO(file_content)
            elif mode == "w":
                yield state["out"]

    client = fuzzbucket_client.__main__.Client()
    monkeypatch.setattr(client, "_credentials_file", FakeFile())
    if env_credentials is not None:
        client._env["FUZZBUCKET_CREDENTIALS"] = env_credentials

    client._write_credentials(user, secret, name=name)
    assert client._cached_credentials is None

    if env_credentials is not None:
        return

    state["out"].seek(0)
    written = state["out"].read()
    assert "# WARNING:" in written
    for write_match in write_matches:
        assert re.search(write_match, written, re.MULTILINE) is not None


@pytest.mark.parametrize(
    ("env_credentials", "expected"),
    [
        pytest.param(None, "whimsy:doodles", id="from_file"),
        pytest.param("daffy:succotash", "daffy:succotash", id="from_env"),
    ],
)
def test_client__read_credentials(env_credentials, expected):
    client = fuzzbucket_client.__main__.Client()
    if env_credentials is not None:
        client._env["FUZZBUCKET_CREDENTIALS"] = env_credentials
    assert client._cached_credentials is None
    assert client._read_credentials() == expected


@pytest.mark.parametrize(
    ("env_preferences", "matches"),
    [
        pytest.param(
            None,
            ["default_key_alias", "//"],
            id="from_file",
        ),
        pytest.param(
            '{"lapis":"lazuli"}',
            ["lapis"],
            id="from_env",
        ),
        pytest.param('{"oh n', [], id="sad_json_from_env"),
    ],
)
def test_client__read_preferences(env_preferences, matches):
    client = fuzzbucket_client.__main__.Client()
    if env_preferences is not None:
        client._env["FUZZBUCKET_PREFERENCES"] = env_preferences
    assert client._cached_preferences is None
    prefs = client._read_preferences()
    for match in matches:
        assert match in prefs


@pytest.mark.parametrize(
    ("env_preferences", "matches"),
    [
        pytest.param(None, ["elephant"], id="to_file"),
        pytest.param('{"cobblestone":"stairs"}', [], id="not_to_env"),
    ],
)
def test_client__write_preferences(env_preferences, matches):
    client = fuzzbucket_client.__main__.Client()
    if env_preferences is not None:
        client._env["FUZZBUCKET_PREFERENCES"] = env_preferences
    assert client._cached_preferences is None
    client._write_preferences({"elephant": "dance"})
    prefs = client._read_preferences()
    for match in matches:
        assert match in prefs
