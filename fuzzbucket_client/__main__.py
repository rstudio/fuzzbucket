#!/usr/bin/env python3
"""
A client for fuzzbucket.

In addition to arguments passed via command line, configuration is accepted via
the following environment variables:

    FUZZBUCKET_URL (REQUIRED) - [string URL] the fuzzbucket instance including path
                                prefix, e.g.:
                                https://xyz123.execute-api.us-east-1.amazonaws.com/prod

    FUZZBUCKET_SSM            - [string "always"/"auto"/"never"] control when to use an
                                SSM proxy when a given box does not have a public DNS
                                name (default="auto")

    FUZZBUCKET_CREDENTIALS    - [string "username:secret"] credentials like those in
                                ~/.cache/fuzzbucket/credentials (no default)

    FUZZBUCKET_LOG_LEVEL      - [string] log level name (default="INFO")

    FUZZBUCKET_PREFERENCES    - [json] preferences value like that in
                                ~/.cache/fuzzbucket/preferences (no default)

"""
import argparse
import configparser
import contextlib
import datetime
import enum
import fnmatch
import getpass
import io
import json
import logging
import os
import pathlib
import re
import shlex
import sys
import textwrap
import typing
import urllib.parse
import urllib.request
import webbrowser

from . import __version__, datetime_ext

MIN_TTL = datetime.timedelta(minutes=10)
MAX_TTL = datetime.timedelta(weeks=12)
SECRET_TOKEN_SIZE_ENCODED = 42
TTL_HELP = """\
The --ttl argument may be given values that include the following:

seconds as integers or floats
    123
    456.78

datetime.timedelta strings
    '1 day, 2:34:56'
    '12:34:56'
    '123 days, 4:57:18'

datetime.timedelta-like strings as alternating <value> <unit>
    '1 week, 23 days, 45 minutes 6 seconds'
    '12 weeks, 3.9 days 4 hour 56 minutes'


The top-level --check-ttl flag may be used to check a ttl value prior to using it with
this command.
"""


def default_client() -> "Client":
    return Client()


def config_logging(level: int = logging.INFO, stream: typing.TextIO = sys.stderr):
    logging.basicConfig(
        stream=stream,
        style="{",
        format="# {name}:{levelname}:{asctime}:: {message}",
        datefmt="%Y-%m-%dT%H%M%S",
        level=level,
    )


def log_level() -> int:
    return getattr(
        logging,
        os.environ.get("FUZZBUCKET_LOG_LEVEL", "INFO").strip().upper(),
    )


def _env_creds_log(msg: str):  # pragma: no cover
    if sys.stdout.isatty():
        log.warning(msg)
        return
    log.debug(msg)


def _instance_tags_from_string(input_string: str) -> dict[str, str]:
    instance_tags = {}
    for pair in filter(
        lambda s: s != "",
        [s.strip() for s in input_string.split(",")],
    ):
        if ":" not in pair:
            raise ValueError(f"instance_tag={pair!r} is not a '<key>:<value>' pair")
        key, value = [
            urllib.parse.unquote(str(s.strip()))
            for s in pair.strip().split(":", maxsplit=1)
        ]
        log.debug(f"adding instance tag key={key!r} value={value!r}")
        instance_tags[key] = value
    return instance_tags


def _normalize_known_args(known_args: argparse.Namespace) -> argparse.Namespace:
    cloned_args = argparse.Namespace(**known_args.__dict__)

    if hasattr(cloned_args, "user") and cloned_args.user is not None:
        username = str(cloned_args.user).strip()
        lower_username = username.lower()
        if lower_username != username:
            log.warning(
                "mixed-case and upper-case usernames are known to contribute to"
                + "weirdness; the lower-case string will be used instead "
                + f"(username={username!r}"
            )
            cloned_args.user = lower_username

    return cloned_args


def utcnow() -> datetime.datetime:
    return datetime.datetime.utcnow()


log = logging.getLogger("fuzzbucket")


class CustomHelpFormatter(
    argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter
): ...


def main(sysargs: list[str] = sys.argv[:]) -> int:
    client = default_client()
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=CustomHelpFormatter,
    )
    parser.add_argument(
        "--version", action="store_true", help="print the version and exit"
    )
    parser.add_argument(
        "--check-ttl",
        type=datetime_ext.parse_timedelta,
        default=None,
        help="check a ttl value and exit, presumably before using it with a command "
        + "that supports ttl",
    )
    parser.add_argument(
        "-j",
        "--output-json",
        action="store_true",
        default=False,
        help="format all output as json",
    )
    parser.add_argument(
        "-D",
        "--debug",
        action="store_true",
        default=log_level() == logging.DEBUG,
        help="enable debug logging",
    )
    subparsers = parser.add_subparsers(
        title="commands",
    )

    parser_login = subparsers.add_parser(
        "login", help="login via auth provider", formatter_class=CustomHelpFormatter
    )
    parser_login.add_argument("user", help="username/email used with auth provider")
    parser_login.add_argument(
        "-n",
        "--name",
        default=None,
        help="human-friendly name to give to credentials entry",
    )
    parser_login.set_defaults(func=client.login)
    parser_login.epilog = textwrap.dedent(
        """
        NOTE: Use the exact letter casing expected by the auth provider to
        avoid weirdness.
        """
    )

    parser_logout = subparsers.add_parser(
        "logout",
        help="logout (from fuzzbucket *only*)",
        formatter_class=CustomHelpFormatter,
    )
    parser_logout.set_defaults(func=client.logout)

    parser_create = subparsers.add_parser(
        "create",
        aliases=["c", "new"],
        help="create a box",
        description="\n\n".join(["Create a box.", TTL_HELP]),
        formatter_class=CustomHelpFormatter,
    )
    parser_create.add_argument(
        "image", default=Client.default_image_alias, help="image alias or full AMI id"
    )
    parser_create.add_argument(
        "-n", "--name", help="custom name for box (generated if omitted)"
    )
    parser_create.add_argument(
        "-c",
        "--connect",
        action="store_true",
        help="add connect-specific security group for accessing ports 3939 and 13939",
    )
    parser_create.add_argument(
        "-T",
        "--ttl",
        type=datetime_ext.parse_timedelta,
        default=datetime.timedelta(hours=4),
        help="set the TTL for the box, after which it will be reaped ",
    )
    parser_create.add_argument("-t", "--instance-type", default=None)
    parser_create.add_argument(
        "-S",
        "--root-volume-size",
        default=None,
        help="set the root volume size (in GB)",
    )
    parser_create.add_argument(
        "-k",
        "--key-alias",
        default=None,
        help="specify which key alias to use",
    )
    parser_create.add_argument(
        "-X",
        "--instance-tags",
        default=None,
        help="key:value comma-delimited instance tags (optionally url-encoded)",
    )
    parser_create.set_defaults(func=client.create)

    parser_list = subparsers.add_parser(
        "ls",
        aliases=["l", "list"],
        help="list matching boxes",
        formatter_class=CustomHelpFormatter,
    )
    parser_list.add_argument("box_match", nargs="?")
    parser_list.set_defaults(func=client.ls)

    parser_update = subparsers.add_parser(
        "update",
        aliases=["u", "up"],
        help="update matching boxes",
        description="\n\n".join(["Update matching boxes.", TTL_HELP]),
        formatter_class=CustomHelpFormatter,
    )
    parser_update.add_argument(
        "-T",
        "--ttl",
        type=datetime_ext.parse_timedelta,
        default=None,
        help="set the new TTL for the matching boxes relative to the current time, "
        + "after which they will be reaped",
    )
    parser_update.add_argument(
        "-X",
        "--instance-tags",
        default=None,
        help="key:value comma-delimited instance tags (optionally url-encoded)",
    )
    parser_update.add_argument("box_match")
    parser_update.set_defaults(func=client.update)

    parser_delete = subparsers.add_parser(
        "delete",
        aliases=["d", "del", "rm", "remove"],
        help="delete matching boxes",
        formatter_class=CustomHelpFormatter,
    )
    parser_delete.add_argument("box_match")
    parser_delete.set_defaults(func=client.delete)

    parser_reboot = subparsers.add_parser(
        "reboot",
        aliases=["restart"],
        help="reboot a box",
        formatter_class=CustomHelpFormatter,
    )
    parser_reboot.add_argument("box")
    parser_reboot.set_defaults(func=client.reboot)

    parser_ssh = subparsers.add_parser(
        "ssh", help="ssh into a box", formatter_class=CustomHelpFormatter
    )
    parser_ssh.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress box info header",
    )
    parser_ssh.add_argument(
        "--ssm",
        default=_TrinaryBehavior.AUTO,
        type=_TrinaryBehavior,
        help="open session via Amazon SSM proxy",
    )
    parser_ssh.usage = "usage: %(prog)s [-hq|--ssm] box [ssh-arguments]"
    parser_ssh.description = textwrap.dedent(
        """
        ssh into a box, optionally passing arbitrary commands as positional
        arguments.  Additionally, stdio streams will be inherited by the ssh
        process in order to support piping.
        """
    )
    parser_ssh.epilog = textwrap.dedent(
        """
        NOTE: If no login is provided via the "-l" ssh option, a value will
        be guessed based on the box image alias.
        """
    )
    parser_ssh.add_argument("box")
    parser_ssh.set_defaults(func=client.ssh)

    parser_scp = subparsers.add_parser(
        "scp",
        help="scp things into or out of a box",
        formatter_class=CustomHelpFormatter,
    )
    parser_scp.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress box info header",
    )
    parser_scp.add_argument(
        "--ssm",
        default=_TrinaryBehavior.AUTO,
        type=_TrinaryBehavior,
        help="open session via Amazon SSM proxy",
    )
    parser_scp.usage = "usage: %(prog)s [-hq|--ssm] box [scp-arguments]"
    parser_scp.description = textwrap.dedent(
        """
        scp things into or out of a box, optionally passing arbitrary commands
        as positional arguments. Additionally, stdio streams will be inherited
        by the scp process in order to support piping.
        """
    )
    parser_scp.epilog = textwrap.dedent(
        """
        NOTE: If no login is provided in at least one of the source or
        destination arguments, a value will be guessed based on the box image
        alias.

        IMPORTANT: The fully-qualified address of the box will be substituted in
        the remaining command arguments wherever the literal "__BOX__" appears,
        e.g.:

        the command:
            %(prog)s boxname -r ./some/local/path __BOX__:/tmp/

        becomes:
            scp -r ./some/local/path user@boxname.fully.qualified.example.com:/tmp/

        the command:
            %(prog)s boxname -r 'altuser@__BOX__:/var/log/*.log' ./some/local/path/

        becomes:
            scp -r altuser@boxname.fully.qualified.example.com:/var/log/*.log \\
                   ./some/local/path/
        """
    )
    parser_scp.add_argument("box")
    parser_scp.set_defaults(func=client.scp)

    parser_create_alias = subparsers.add_parser(
        "create-alias",
        aliases=["ca"],
        help="create an image alias",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser_create_alias.add_argument("alias")
    parser_create_alias.add_argument("ami")
    parser_create_alias.set_defaults(func=client.create_alias)

    parser_list_aliases = subparsers.add_parser(
        "list-aliases",
        aliases=["la"],
        help="list known image aliases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser_list_aliases.set_defaults(func=client.list_aliases)

    parser_delete_alias = subparsers.add_parser(
        "delete-alias",
        aliases=["da"],
        help="delete an image alias",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser_delete_alias.add_argument("alias")
    parser_delete_alias.set_defaults(func=client.delete_alias)

    parser_get_key = subparsers.add_parser(
        "get-key",
        aliases=["gk"],
        help="get an ssh public key id and fingerprint as stored in EC2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser_get_key.add_argument(
        "--alias",
        "-a",
        type=str,
        default="default",
        help="the alias of the key to get",
    )
    parser_get_key.set_defaults(func=client.get_key)

    parser_set_key = subparsers.add_parser(
        "set-key",
        aliases=["sk"],
        help="set the local default key alias to use when creating boxes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser_set_key.add_argument(
        "--alias",
        "-a",
        type=str,
        default="default",
        help="the alias of the key to set as the local default",
    )
    parser_set_key.set_defaults(func=client.set_key)

    parser_list_keys = subparsers.add_parser(
        "list-keys",
        aliases=["lk"],
        help="list ssh public keys stored in EC2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser_list_keys.set_defaults(func=client.list_keys)

    parser_add_key = subparsers.add_parser(
        "add-key",
        aliases=["ak"],
        help="add an ssh public key to EC2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser_add_key.add_argument(
        "--alias",
        "-a",
        type=str,
        default="default",
        help="the alias of the key to add",
    )
    parser_add_key.add_argument(
        "--filename",
        "-f",
        type=lambda f: pathlib.Path(f).expanduser(),
        default=pathlib.Path("~/.ssh/id_rsa.pub").expanduser(),
        help="file path of the ssh public key",
    )
    parser_add_key.set_defaults(func=client.add_key)

    parser_delete_key = subparsers.add_parser(
        "delete-key",
        aliases=["dk"],
        help="delete an ssh public key stored in EC2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser_delete_key.add_argument(
        "--alias",
        "-a",
        type=str,
        default="default",
        help="the alias of the key to delete",
    )
    parser_delete_key.set_defaults(func=client.delete_key)

    parser_whoami = subparsers.add_parser(
        "whoami", aliases=["who", "w"], help="who are you (logged in as)?"
    )
    parser_whoami.set_defaults(func=client.whoami)

    parser_api = subparsers.add_parser(
        "api", help="make an arbitrary HTTP request to the fuzzbucket API"
    )
    parser_api.add_argument(
        "-X", "--request", default="GET", help="request method to use"
    )
    parser_api.add_argument(
        "-H", "--header", default=[], action="append", help="pass custom header(s)"
    )
    parser_api.add_argument(
        "-i",
        "--include",
        action="store_true",
        help="include response headers in the output",
    )
    parser_api.add_argument(
        "url", help="full URL or request path to be joined to FUZZBUCKET_URL"
    )
    parser_api.set_defaults(func=client.api)

    known_args, unknown_args = parser.parse_known_args(sysargs[1:])
    known_args = _normalize_known_args(known_args)
    config_logging(level=logging.DEBUG if known_args.debug else logging.INFO)
    if known_args.version:
        print(f"fuzzbucket-client {__version__.__version__}")
        return 0
    if known_args.output_json:
        client.data_format = _DataFormats.JSON
    if known_args.check_ttl:
        client.show_valid_ttl(known_args.check_ttl)
        return 0
    if not hasattr(known_args, "func"):
        log.debug(f"no subcommand func defined in namespace={known_args!r}")
        parser.print_help()
        return 2
    if known_args.func(known_args, unknown_args):
        return 0
    return 86


def _print_auth_hint():
    print(
        textwrap.dedent(
            """
        Please run the following command with your username/email
        to grant access to Fuzzbucket:

            fuzzbucket-client login {username/email}

        If you believe you are already logged in, there is a chance
        that you logged in with different letter casing than what
        the auth provider expects. Please double check the letter
        casing of your username and then retry login after removing
        your existing login data:

            fuzzbucket-client logout

            fuzzbucket-client login {username/email}
        """
        )
    )


def _pjoin(*parts: str) -> str:
    return "/".join(parts)


NOSETUP_COMMANDS = ("login",)


def _command(method):
    def handle_exc(exc):
        msg = f"command {method.__name__!r} failed"
        if log_level() == logging.DEBUG:
            log.exception(msg)
        else:
            log.error(f"{msg} err={exc!r}")
        return False

    def wrapper(self, known_args, unknown_args):
        try:
            if method.__name__ not in NOSETUP_COMMANDS:
                self._setup()
            result = method(self, known_args, unknown_args)
            self._finalize()
            return result
        except urllib.request.HTTPError as exc:
            try:
                response = json.load(exc)
                log.error(
                    f"command {method.__name__!r} failed err={response.get('error')!r}"
                )
                if exc.code == 403:
                    _print_auth_hint()
                return False
            except Exception as exc:
                return handle_exc(exc)
        except CredentialsError as exc:
            log.error(f"command {method.__name__!r} failed err={exc}")
            _print_auth_hint()
            return False
        except Exception as exc:
            return handle_exc(exc)

    return wrapper


class CredentialsError(ValueError):
    def __init__(self, url: str, credentials_path: str) -> None:
        self.url = url
        self.credentials_path = credentials_path

    def __str__(self) -> str:
        return (
            f"No credentials found for url={self.url!r} in "
            + f"file={self.credentials_path!r}"
        )


class _DataFormats(enum.Enum):
    INI = "ini"
    JSON = "json"


class _TrinaryBehavior(enum.Enum):
    ALWAYS = "always"
    AUTO = "auto"
    NEVER = "never"

    def __str__(self) -> str:
        return self.value


class _Preferences(enum.Enum):
    DEFAULT_KEY_ALIAS = "default_key_alias"


if sys.version_info >= (3, 10):
    Box: typing.TypeAlias = dict[str, typing.Union[str, None, int, dict[str, str]]]
else:
    Box = typing.Any


def execvp(*args, **kwargs):
    os.execvp(*args, **kwargs)


class Client:
    default_instance_type = "t3.small"
    default_image_alias = "ubuntu18"
    default_instance_types = {
        "centos6": "t2.small",
        "rhel6": "t2.small",
        "sles12": "t2.small",
        None: default_instance_type,
    }
    default_key_alias = "default"
    default_ssh_user = "ec2-user"
    default_ssh_users = {
        "centos": "centos",
        "rocky": "rocky",
        "rhel": default_ssh_user,
        "sles": default_ssh_user,
        "suse": default_ssh_user,
        "almalinux": default_ssh_user,
        "amzn": default_ssh_user,
        "ubuntu": "ubuntu",
    }

    def __init__(
        self,
        env: typing.Optional[dict[str, str]] = None,
    ):
        self._env = env if env is not None else dict(os.environ)
        self._cached_url_opener = None
        self._cached_credentials = None
        self._patched_credentials_file = None
        self._cached_preferences = None
        self.data_format = _DataFormats.INI

    def _setup(self):
        assert self._url
        if self._credentials in (None, ""):
            raise CredentialsError(self._url, str(self._credentials_file))

    def _finalize(self):
        self._write_preferences(self._preferences)

    def show_valid_ttl(self, ttl):
        print(self._format_valid_ttl(ttl), end="")
        return True

    @_command
    def login(self, known_args, _):
        log.debug(f"starting login flow for user={known_args.user}")
        login_url = "?".join(
            [
                _pjoin(self._url, "_login"),
                urllib.parse.urlencode(dict(user=known_args.user)),
            ]
        )
        webbrowser.open(login_url)
        print(
            textwrap.dedent(
                f"""
            Attempting to open the following URL in a browser:

                {login_url}

            Please follow the OAuth2 flow and then paste the 'secret' provided
            by fuzzbucket.
        """
            )
        )
        secret = None
        while secret is None:
            try:
                raw_secret = getpass.getpass("secret: ").strip()
                if len(raw_secret) != SECRET_TOKEN_SIZE_ENCODED:
                    print("Invalid secret provided. Please try again.")
                    continue
                secret = raw_secret
            except KeyboardInterrupt:
                return False
        self._write_credentials(known_args.user, secret, name=known_args.name)
        print(f"Login successful user={known_args.user!r}")
        return True

    @_command
    def logout(self, *_):
        log.debug(f"starting logout for user={self._user!r}")
        req = self._build_request(_pjoin(self._url, "_logout"), method="POST")
        with self._urlopen(req) as response:
            _ = response.read()
        log.info(f"logged out user={self._user!r}")
        return True

    @_command
    def ls(self, known_args: argparse.Namespace, _):
        log.debug(f"fetching boxes for user={self._user!r}")

        matching_boxes = self._find_boxes(known_args.box_match)

        if matching_boxes is None:
            log.error(f"no boxes found matching {known_args.box_match!r}")

            return False

        log.info(f"fetched boxes for user={self._user!r} count={len(matching_boxes)}")

        print(self._format_boxes(matching_boxes), end="")

        return True

    @_command
    def create(self, known_args, _):
        key_alias = self._preferences.get(
            _Preferences.DEFAULT_KEY_ALIAS.value, self.default_key_alias
        )

        if known_args.key_alias is not None:
            key_alias = known_args.key_alias

        self._preferences[_Preferences.DEFAULT_KEY_ALIAS.value] = key_alias

        payload = {
            "instance_type": known_args.instance_type,
            "key_alias": key_alias,
        }

        if known_args.image.startswith("ami-"):
            payload["ami"] = known_args.image
        else:
            payload["image_alias"] = known_args.image

        if known_args.root_volume_size is not None:
            if not str(known_args.root_volume_size).isdigit():
                log.error(
                    f"root_volume_size={known_args.root_volume_size!r} is not numeric"
                )
                return False

            payload["root_volume_size"] = int(known_args.root_volume_size)

        if payload["instance_type"] is None:
            payload["instance_type"] = self.default_instance_types.get(
                payload.get("image_alias"),
                self.default_instance_type,
            )
        if known_args.connect:
            payload["connect"] = "1"
        if known_args.name != "":
            payload["name"] = known_args.name
        if known_args.instance_tags:
            payload["instance_tags"] = _instance_tags_from_string(
                known_args.instance_tags
            )
        if known_args.ttl.total_seconds() < MIN_TTL.total_seconds():
            log.error(f"ttl={known_args.ttl!r} is below the minimum of {MIN_TTL}")
            return False
        if known_args.ttl.total_seconds() > MAX_TTL.total_seconds():
            log.error(f"ttl={known_args.ttl!r} is above the maximum of {MAX_TTL}")
            return False
        payload["ttl"] = str(int(known_args.ttl.total_seconds()))
        req = self._build_request(
            _pjoin(self._url, "box/"),
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        raw_response = {}
        try:
            with self._urlopen(req) as response:
                raw_response = json.load(response)
            log.info(f"created box for user={self._user!r}")
        except urllib.request.HTTPError as exc:
            if exc.code == 409:
                log.warning("matching box already exists")
                raw_response = json.load(exc)
            else:
                raise exc

        print(self._format_boxes(raw_response["boxes"]), end="")
        return True

    @_command
    def update(self, known_args, _):
        matching_boxes = self._find_boxes(known_args.box_match)

        if matching_boxes is None:
            log.error(f"no boxes found matching {known_args.box_match!r}")
            return False

        payload = {}

        if known_args.ttl:
            if known_args.ttl.total_seconds() < MIN_TTL.total_seconds():
                log.error(f"ttl={known_args.ttl!r} is below the minimum of {MIN_TTL}")
                return False

            if known_args.ttl.total_seconds() > MAX_TTL.total_seconds():
                log.error(f"ttl={known_args.ttl!r} is above the maximum of {MAX_TTL}")
                return False

        if known_args.instance_tags:
            payload["instance_tags"] = _instance_tags_from_string(
                known_args.instance_tags
            )

        if len(payload) == 0 and known_args.ttl is None:
            log.error(f"no updates specified for {known_args.box_match!r}")
            return False

        for matching_box in matching_boxes:
            box_payload = payload.copy()

            if known_args.ttl:
                box_age = datetime_ext.parse_timedelta(matching_box["age"])
                box_payload["ttl"] = str(
                    int(box_age.total_seconds() + known_args.ttl.total_seconds())
                )
                log.debug(
                    f"setting ttl={box_payload['ttl']!r} for "
                    + f"matching_box={matching_box!r}"
                )

            req = self._build_request(
                _pjoin(self._url, "box", matching_box["instance_id"]),
                data=json.dumps(box_payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="PUT",
            )

            with self._urlopen(req) as response:
                _ = response.read()

            log.info(f"updated box for user={self._user!r} name={matching_box['name']}")
            print(self._format_boxes([matching_box]), end="")

        return True

    @_command
    def delete(self, known_args, _):
        matching_boxes = self._find_boxes(known_args.box_match)
        if matching_boxes is None:
            log.error(f"no boxes found matching {known_args.box_match!r}")
            return False
        for matching_box in matching_boxes:
            req = self._build_request(
                _pjoin(self._url, "box", matching_box["instance_id"]),
                method="DELETE",
            )
            with self._urlopen(req) as response:
                _ = response.read()
            log.info(f"deleted box for user={self._user!r} name={matching_box['name']}")
            print(self._format_boxes([matching_box]), end="")
        return True

    @_command
    def reboot(self, known_args, _):
        matching_box = self._find_box(known_args.box)
        if matching_box is None:
            log.error(f"no box found matching {known_args.box!r}")
            return False
        req = self._build_request(
            _pjoin(self._url, "box", matching_box["instance_id"], "reboot"),
            method="POST",
        )
        with self._urlopen(req) as response:
            _ = response.read()
        log.info(f"rebooted box for user={self._user!r} box={matching_box['name']!r}")
        print(self._format_boxes([matching_box]), end="")
        return True

    @_command
    def ssh(self, known_args, unknown_args):
        matching_box, hostname, needs_ssm, ok = self._resolve_sshable_box(
            known_args.box, known_args.ssm
        )

        if not ok:
            return False

        assert matching_box is not None

        ssh_command, ok = self._build_ssh_command(
            matching_box, hostname, needs_ssm, unknown_args
        )

        if not ok:
            return False

        if not known_args.quiet:
            log.info(
                f"sshing into matching_box={matching_box['name']!r} "
                + f"ssh_command={ssh_command!r}"
            )
            print(self._format_boxes([matching_box]), end="")

        sys.stdout.flush()
        sys.stderr.flush()

        execvp("ssh", ssh_command)

        return True  # NOTE: this is unreachable under normal circumstances

    @_command
    def scp(self, known_args, unknown_args):
        matching_box, hostname, needs_ssm, ok = self._resolve_sshable_box(
            known_args.box, known_args.ssm
        )

        if not ok:
            return False

        assert matching_box is not None

        scp_command = self._build_scp_command(
            matching_box, hostname, needs_ssm, unknown_args
        )

        log.info(
            f"scping with matching_box={matching_box['name']!r} "
            + f"scp_command={scp_command!r}"
        )

        print(self._format_boxes([matching_box]), end="")

        sys.stdout.flush()
        sys.stderr.flush()

        execvp("scp", scp_command)

        return True  # NOTE: this is unreachable under normal circumstances

    @_command
    def list_aliases(self, *_):
        req = self._build_request(_pjoin(self._url, "image-alias/"))
        raw_response = {}
        with self._urlopen(req) as response:
            raw_response = json.load(response)
        if "image_aliases" not in raw_response:
            log.error("failed to fetch image aliases")
            return False
        print(self._format_image_aliases(raw_response["image_aliases"]), end="")
        return True

    @_command
    def create_alias(self, known_args, _):
        payload = {"alias": known_args.alias, "ami": known_args.ami}
        req = self._build_request(
            _pjoin(self._url, "image-alias/"),
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        raw_response = {}
        with self._urlopen(req) as response:
            raw_response = json.load(response)
        log.debug(f"raw created alias response={raw_response!r}")
        if "image_aliases" not in raw_response:
            log.error("failed to create image alias")
            return False
        for key, value in raw_response["image_aliases"].items():
            log.info(f"created alias for user={self._user!r} alias={key} ami={value}")
        print(self._format_image_aliases(raw_response["image_aliases"]), end="")
        return True

    @_command
    def delete_alias(self, known_args, _):
        req = self._build_request(
            _pjoin(self._url, "image-alias", known_args.alias), method="DELETE"
        )
        with self._urlopen(req) as response:
            _ = response.read()
        log.info(f"deleted alias for user={self._user!r} alias={known_args.alias}")
        return True

    @_command
    def get_key(self, known_args, _):
        key_alias = self._preferences.get(
            _Preferences.DEFAULT_KEY_ALIAS.value, self.default_key_alias
        )

        if known_args.alias is not None:
            key_alias = known_args.alias

        self._preferences[_Preferences.DEFAULT_KEY_ALIAS.value] = key_alias

        req = self._build_request(_pjoin(self._url, "key", key_alias), method="GET")

        raw_response = {}
        with self._urlopen(req) as response:
            raw_response = json.load(response)

        print(self._format_keys([raw_response["key"]]), end="")

        return True

    @_command
    def set_key(self, known_args, _):
        self._preferences[_Preferences.DEFAULT_KEY_ALIAS.value] = known_args.alias
        log.info(
            f"set key with alias={known_args.alias!r} as local default "
            + f"for user={self._user!r}"
        )
        return True

    @_command
    def list_keys(self, *_):
        req = self._build_request(_pjoin(self._url, "key/"), method="GET")
        raw_response = {}
        with self._urlopen(req) as response:
            raw_response = json.load(response)

        print(self._format_keys(raw_response["keys"]), end="")

        return True

    @_command
    def add_key(self, known_args, _):
        key_alias = known_args.alias

        if key_alias is None:
            key_alias = known_args.filename.name.lower().replace("_rsa.pub", "")

        if key_alias == "id":
            key_alias = self.default_key_alias

        self._preferences[_Preferences.DEFAULT_KEY_ALIAS.value] = key_alias

        payload = {"key_material": known_args.filename.read_text().strip()}

        req = self._build_request(
            _pjoin(self._url, "key", key_alias),
            method="PUT",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        raw_response = {}
        with self._urlopen(req) as response:
            raw_response = json.load(response)

        print(self._format_keys([raw_response["key"]]), end="")

        return True

    @_command
    def delete_key(self, known_args, _):
        key_alias = self._preferences.get(
            _Preferences.DEFAULT_KEY_ALIAS.value, self.default_key_alias
        )

        if known_args.alias is not None:
            key_alias = known_args.alias

        self._preferences[_Preferences.DEFAULT_KEY_ALIAS.value] = key_alias

        req = self._build_request(_pjoin(self._url, "key", key_alias), method="DELETE")
        raw_response = {}
        with self._urlopen(req) as response:
            raw_response = json.load(response)
        log.info(f"deleted key with alias={key_alias!r} for user={self._user!r}")
        print(self._format_keys([raw_response["key"]]), end="")
        return True

    @_command
    def whoami(self, *_):
        req = self._build_request(_pjoin(self._url, "whoami"))

        with self._urlopen(req) as response:
            raw_response = json.load(response)

            if "you" in raw_response and raw_response["you"] is not None:
                if self.data_format == _DataFormats.JSON:
                    print(json.dumps(raw_response))

                    return True

                print(raw_response["you"])
                return True

        print("you are not currently logged in")
        return False

    @_command
    def api(self, known_args, _):
        full_url = known_args.url

        if not full_url.startswith("http"):
            full_url = _pjoin(self._url, full_url)

        req = self._build_request(full_url, method=known_args.request)

        for header in known_args.header:
            key, value = header.split(":", maxsplit=1)
            req.headers[key] = value

        with self._urlopen(req) as response:
            if known_args.include:
                for header in response.headers:
                    print(f"{header}: {response.headers[header]}")

                print("")

            for chunk in response:
                sys.stdout.write(chunk.decode("utf-8"))

        return True

    def _find_box(self, box_search):
        results = self._find_boxes(box_search)

        if results is None:
            return None

        return results[0]

    def _find_boxes(self, box_search):
        boxes = self._list_boxes()

        if box_search is None:
            return boxes

        results = []

        for box in boxes:
            log.debug(f"finding box_search={box_search!r} considering box={box!r}")

            if box.get("name") is not None and fnmatch.fnmatchcase(
                box["name"], box_search
            ):
                results.append(box)

                continue

            if box.get("image_alias") is not None and fnmatch.fnmatchcase(
                box["image_alias"], box_search
            ):
                results.append(box)

                continue

        if len(results) == 0:
            return None

        return results

    def _list_boxes(self):
        req = self._build_request(_pjoin(self._url, "box/"))
        raw_response = {}
        with self._urlopen(req) as response:
            raw_response = json.load(response)
        return raw_response["boxes"]

    @contextlib.contextmanager
    def _urlopen(self, request):
        log.debug(
            f"attempting request user={self._user!r} method={request.method!r} "
            + f"url={request.full_url!r}"
        )
        with urllib.request.urlopen(request) as response:
            yield response

    @property
    def _url(self) -> str:
        value = self._env.get("FUZZBUCKET_URL")
        if value is None:
            raise ValueError("missing FUZZBUCKET_URL")
        return value

    @property
    def _preferences(self):
        if self._cached_preferences is None:
            self._cached_preferences = self._read_preferences()
        return self._cached_preferences

    def _read_preferences(self):
        try:
            env_prefs = self._env.get("FUZZBUCKET_PREFERENCES")
            if env_prefs is not None:
                log.debug("reading preferences directly from FUZZBUCKET_PREFERENCES")
                return json.loads(env_prefs)
            self._preferences_file.touch()
            with self._preferences_file.open() as infile:
                return json.load(infile)
        except json.decoder.JSONDecodeError:
            log.debug("failed to load preferences; returning empty preferences")
            return {}

    def _write_preferences(self, preferences):
        if self._env.get("FUZZBUCKET_PREFERENCES") is not None:
            log.debug(
                "skipping writing preferences due to presence of FUZZBUCKET_PREFERENCES"
            )
            return

        preferences["//"] = "WARNING: this file is generated"
        preferences["__updated_at__"] = str(utcnow())

        with self._preferences_file.open("w") as outfile:
            json.dump(preferences, outfile, sort_keys=True, indent=2)

        self._cached_preferences = None

    @property
    def _preferences_file(self):
        file = pathlib.Path("~/.cache/fuzzbucket/preferences").expanduser()
        file.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        return file

    @property
    def _credentials_section(self):
        return f'server "{self._url}"'

    @property
    def _credentials(self) -> str:
        if self._cached_credentials is None:
            self._cached_credentials = self._read_credentials()
        assert self._cached_credentials is not None
        return self._cached_credentials

    @property
    def _credentials_file(self):
        if self._patched_credentials_file is not None:
            return self._patched_credentials_file
        file = pathlib.Path("~/.cache/fuzzbucket/credentials").expanduser()
        file.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        return file

    @_credentials_file.setter
    def _credentials_file(self, value):
        self._patched_credentials_file = value

    def _read_credentials(self):
        if self._env.get("FUZZBUCKET_CREDENTIALS") is not None:
            _env_creds_log("reading credentials directly from FUZZBUCKET_CREDENTIALS")
            return self._env.get("FUZZBUCKET_CREDENTIALS")

        self._credentials_file.touch()
        with self._credentials_file.open() as infile:
            creds = configparser.ConfigParser()
            creds.read_file(infile)

            if self._credentials_section not in creds.sections():
                return ""

            return creds.get(self._credentials_section, "credentials")

    def _write_credentials(self, user, secret, name=None):
        if self._env.get("FUZZBUCKET_CREDENTIALS") is not None:
            _env_creds_log(
                "skipping writing credentials due to presence of FUZZBUCKET_CREDENTIALS"
            )

            return

        creds = configparser.ConfigParser()

        if self._credentials_file.exists():
            with self._credentials_file.open() as infile:
                creds.read_file(infile)

        if self._credentials_section not in creds.sections():
            creds.add_section(self._credentials_section)

        creds.set(self._credentials_section, "credentials", f"{user}:{secret}")

        if name is not None:
            creds.set(self._credentials_section, "name", str(name))

        with self._credentials_file.open("w") as outfile:
            outfile.write(
                "# WARNING: this file is generated " + f"(last update {utcnow()})\n"
            )
            creds.write(outfile)

        self._cached_credentials = None

    @property
    def _user(self):
        return self._credentials.split(":")[0].split("--")[0]

    @property
    def _secret(self):
        return self._credentials.split(":")[1]

    def _build_request(self, url, data=None, headers=None, method="GET"):
        headers = headers if headers is not None else {}

        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        req.headers["fuzzbucket-user"] = self._user
        req.headers["fuzzbucket-secret"] = self._secret

        return req

    def _resolve_sshable_box(
        self, box_name: str, ssm: _TrinaryBehavior
    ) -> tuple[typing.Optional[Box], str, bool, bool]:
        matching_box = self._find_box(box_name)

        if matching_box is None:
            log.error(f"no box found matching {box_name!r}")

            return None, "", False, False

        hostname: typing.Optional[str] = None
        needs_ssm: bool = False

        if ssm == _TrinaryBehavior.ALWAYS:
            hostname = matching_box.get("instance_id")
            needs_ssm = True

        elif ssm == _TrinaryBehavior.NEVER:
            hostname = matching_box.get("public_dns_name")

        else:
            hostname = matching_box.get("public_dns_name")

            if hostname is None:
                hostname = matching_box.get("instance_id")
                needs_ssm = True

        if hostname is None:
            log.error(f"no hostname name found for box={matching_box['name']}")

            return None, "", False, False

        return matching_box, hostname, needs_ssm, True

    def _build_ssh_command(
        self, box: Box, hostname: str, needs_ssm: bool, unknown_args: list[str]
    ) -> tuple[list[str], bool]:
        if "-l" not in unknown_args:
            unknown_args = [
                "-l",
                self._guess_ssh_user(
                    box.get("image_alias", self.default_image_alias),
                    self.default_ssh_user,
                ),
            ] + unknown_args

        return (
            typing.cast(
                list[str],
                ["ssh", hostname]
                + self._with_ssh_opts(
                    box,
                    needs_ssm,
                    unknown_args,
                ),
            ),
            True,
        )

    def _build_scp_command(
        self, box: Box, hostname: str, needs_ssm: bool, unknown_args: list[str]
    ) -> list[str]:
        for i, value in enumerate(unknown_args):
            if "__BOX__" not in value:
                continue

            box_value = hostname

            if "@" not in value:
                box_value = "@".join(
                    [
                        self._guess_ssh_user(
                            box.get("image_alias", self.default_image_alias),
                            self.default_ssh_user,
                        ),
                        box_value,
                    ]
                )

            unknown_args[i] = value.replace("__BOX__", box_value)

        return ["scp"] + self._with_ssh_opts(
            box,
            needs_ssm,
            unknown_args,
        )

    def _with_ssh_opts(
        self,
        box: Box,
        needs_ssm: bool,
        unknown_args: list[str],
    ) -> list[str]:
        unknown_args_string = " ".join(unknown_args)
        if (
            re.search(
                " -o StrictHostKeyChecking=.+", unknown_args_string, re.IGNORECASE
            )
            is None
        ):
            unknown_args = ["-o", "StrictHostKeyChecking=no"] + unknown_args

        if (
            re.search(" -o UserKnownHostsFile=.+", unknown_args_string, re.IGNORECASE)
            is None
        ):
            unknown_args = ["-o", "UserKnownHostsFile=/dev/null"] + unknown_args

        if needs_ssm:
            return self._with_ssh_ssm_proxy_command(box, unknown_args)

        return unknown_args

    def _with_ssh_ssm_proxy_command(
        self, box: Box, unknown_args: list[str]
    ) -> list[str]:
        unknown_args_string = " ".join(unknown_args)
        if (
            re.search(" -o ProxyCommand=.+", unknown_args_string, re.IGNORECASE)
            is not None
        ):
            return unknown_args

        aws_region = box.get(
            "region",
            self._env.get(
                "AWS_REGION",
                self._env.get("AWS_DEFAULT_REGION", "us-east-2"),
            ),
        )

        aws_ssm_command = [
            "aws",
            "ssm",
            "start-session",
            "--target",
            str(box["instance_id"]),
            "--region",
            str(aws_region),
            "--document-name",
            "AWS-StartSSHSession",
            "--parameters",
            "portNumber=%p",
        ]
        proxy_command = [
            "sh",
            "-c",
            shlex.quote(" ".join(aws_ssm_command)),
        ]

        return ["-o", f"ProxyCommand={' '.join(proxy_command)}"] + unknown_args

    def _format_boxes(self, boxes):
        return getattr(self, f"_format_boxes_{self.data_format.value}")(boxes)

    def _format_boxes_ini(self, boxes):
        boxes_ini = configparser.ConfigParser()

        for box in boxes:
            boxes_ini.add_section(box["name"])

            if box.get("public_ip") is None:
                box["public_ip"] = "(pending)"

            for key, value in box.items():
                if value is None:
                    continue

                boxes_ini.set(box["name"], str(key), str(value))

        buf = io.StringIO()
        boxes_ini.write(buf)
        buf.seek(0)

        return buf.read()

    def _format_boxes_json(self, boxes):
        return json.dumps({"boxes": {box["name"]: box for box in boxes}}, indent=2)

    def _format_keys(self, keys):
        return getattr(self, f"_format_keys_{self.data_format.value}")(keys)

    def _format_keys_ini(self, keys):
        keys_ini = configparser.ConfigParser()

        for i, key in enumerate(keys):
            key_alias = key.get("alias", f"unaliased-key-{i}")
            keys_ini.add_section(key_alias)

            for attr, value in key.items():
                if value is None:
                    continue

                keys_ini.set(key_alias, str(attr), str(value))

        buf = io.StringIO()
        keys_ini.write(buf)
        buf.seek(0)

        return buf.read()

    def _format_keys_json(self, keys):
        return json.dumps({"keys": keys}, indent=2)

    def _format_image_aliases(self, image_aliases):
        return getattr(self, f"_format_image_aliases_{self.data_format.value}")(
            image_aliases
        )

    def _format_image_aliases_ini(self, image_aliases):
        image_aliases_ini = configparser.ConfigParser()
        image_aliases_ini.add_section("image_aliases")

        for alias, ami in sorted(image_aliases.items()):
            image_aliases_ini.set("image_aliases", alias, ami)

        buf = io.StringIO()
        image_aliases_ini.write(buf)
        buf.seek(0)

        return buf.read()

    def _format_image_aliases_json(self, image_aliases):
        return json.dumps({"image_aliases": dict(image_aliases)}, indent=2)

    def _format_valid_ttl(self, ttl):
        return getattr(self, f"_format_valid_ttl_{self.data_format.value}")(ttl)

    def _format_valid_ttl_ini(self, ttl):
        ttl_ini = configparser.ConfigParser()

        ttl_ini.add_section("ttl")
        ttl_ini.set("ttl", "str", str(ttl))
        ttl_ini.set("ttl", "float", str(ttl.total_seconds()))

        buf = io.StringIO()
        ttl_ini.write(buf)
        buf.seek(0)

        return buf.read()

    def _format_valid_ttl_json(self, ttl):
        return json.dumps(
            {"ttl": {"str": str(ttl), "float": str(ttl.total_seconds())}}, indent=2
        )

    @classmethod
    def _guess_ssh_user(cls, image_alias, default=default_ssh_user) -> str:
        image_alias = image_alias.lower()

        for prefix, user in cls.default_ssh_users.items():
            if image_alias.startswith(prefix):
                return user

        return default


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
