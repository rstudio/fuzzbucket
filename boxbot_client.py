#!/usr/bin/env python3
"""
A client for boxbot.

Configuration is accepted via the following environment variables:

    BOXBOT_URL - string URL of the boxbot instance including path prefix
    BOXBOT_CREDENTIALS - "github-user:boxbot-token" string

"""
import argparse
import contextlib
import base64
import json
import logging
import os
import sys
import urllib.parse
import urllib.request

log = logging.getLogger("boxbot")
logging.basicConfig(
    stream=sys.stdout,
    style="{",
    format="{name}:{levelname}:{asctime}:: {message}",
    datefmt="%Y-%m-%dT%H%M%S",
    level=getattr(logging, os.environ.get("LOG_LEVEL", "info").upper()),
)


def main(sysargs=sys.argv[:]):
    try:
        client = Client()
        parser = argparse.ArgumentParser(
            description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
        )
        subparsers = parser.add_subparsers(title="subcommands", help="additional help")

        parser_list = subparsers.add_parser(
            "list", aliases=["ls"], help="List your boxes."
        )
        parser_list.set_defaults(func=client.list)

        parser_create = subparsers.add_parser("create", help="Create a box.")
        parser_create.add_argument("image_alias", default="ubuntu18")
        parser_create.add_argument(
            "-c",
            "--connect",
            action="store_true",
            help="add connect-specific security group for accessing ports 3939 and 13939",
        )
        parser_create.add_argument("-t", "--instance-type", default="t3.small")
        parser_create.set_defaults(func=client.create)

        parser_delete = subparsers.add_parser("delete", help="Delete a box.")
        parser_delete.add_argument("instance_id")
        parser_delete.set_defaults(func=client.delete)

        args = parser.parse_args(sysargs[1:])
        args.func(args)

        return 0
    except Exception:
        log.exception("oh no")
        return 1


class Client:
    def __init__(self, env=None):
        self._env = env if env is not None else dict(os.environ)
        self._cached_url_opener = None

    def _setup(self):
        if self._url is None:
            raise ValueError("missing url")
        if self._credentials is None:
            raise ValueError("missing credentials")

    def list(self, args):
        self._setup()
        req = self._build_request(self._url)
        raw_response = {}
        with self._urlopen(req) as response:
            raw_response = json.load(response)
        log.info(f"fetched boxes for user={self._user!r}")
        for box in raw_response["boxes"]:
            log.info(
                " ".join([f"{field}={box[field]!r}" for field in sorted(box.keys())])
            )

    def create(self, args):
        self._setup()
        payload = {
            "instance_type": args.instance_type,
            "image_alias": args.image_alias,
        }
        if args.connect:
            payload["connect"] = "1"
        req = self._build_request(
            os.path.join(self._url, "box"),
            data=urllib.parse.urlencode(payload).encode("utf-8"),
            method="POST",
        )
        raw_response = {}
        with self._urlopen(req) as response:
            raw_response = json.load(response)
        log.info(f"created box for user={self._user!r}")
        for box in raw_response["boxes"]:
            log.info(
                " ".join([f"{field}={box[field]!r}" for field in sorted(box.keys())])
            )
            if box["public_ip"] is None:
                log.warning(f"public_ip is has not yet been assigned")

    def delete(self, args):
        self._setup()
        req = self._build_request(
            os.path.join(self._url, "box", args.instance_id), method="DELETE"
        )
        with self._urlopen(req) as response:
            _ = response.read()
        log.info(
            f"deleted box for user={self._user!r} instance_id={args.instance_id!r}"
        )

    @contextlib.contextmanager
    def _urlopen(self, request):
        with urllib.request.urlopen(request) as response:
            yield response

    @property
    def _url(self):
        return self._env.get("BOXBOT_URL")

    @property
    def _credentials(self):
        return self._env.get("BOXBOT_CREDENTIALS")

    @property
    def _user(self):
        return self._credentials.split(":")[0]

    def _build_request(self, url, data=None, headers=None, method="GET"):
        headers = headers if headers is not None else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        if not req.has_header("Authorization"):
            creds_b64 = base64.b64encode(self._credentials.encode("utf-8"))
            creds_b64 = creds_b64.decode("utf-8")
            req.headers["Authorization"] = f"basic {creds_b64}"
        return req


if __name__ == "__main__":
    sys.exit(main())
