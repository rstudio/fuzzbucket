#!/usr/bin/env python3
"""
A client for boxbot.

Configuration is accepted via the following environment variables:

    BOXBOT_URL - string URL of the boxbot instance, including "user:token"
                 credentials and path prefix
"""
import argparse
import base64
import json
import logging
import os
import sys
import urllib.request

log = logging.getLogger("boxbot")
logging.basicConfig(
    stream=sys.stdout,
    style="{",
    format="name={name!r} level={levelname!r} time={asctime!r} msg={message!r}",
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
        parser_create.add_argument("-a", "--image-alias", default="ubuntu18")
        parser_create.add_argument(
            "-c",
            "--connect",
            action="store_true",
            help="add connect-specific security group for accessing ports 3939 and 13939",
        )
        parser_create.add_argument("-t", "--instance-type", default="t3.small")
        parser_create.set_defaults(func=client.create)

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

    def setup(self):
        if self._url is None:
            raise ValueError("missing url")
        if self._credentials is None:
            raise ValueError("missing credentials")

    def list(self, args):
        self.setup()
        raw_response = {}
        req = self._build_request(self._url)
        log.debug(f"built request for url={self._url!r}")
        with urllib.request.urlopen(req) as response:
            raw_response = json.load(response)
        log.info(f"fetched boxes for user={self._user}")
        for box in raw_response["boxes"]:
            log.info(
                " ".join([f"{field}={box[field]}" for field in sorted(box.keys())])
            )

    def create(self, args):
        self.setup()
        pass

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
