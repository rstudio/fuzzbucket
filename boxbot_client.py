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


def default_client():
    return Client()


def main(sysargs=sys.argv[:]):
    try:
        client = default_client()
        parser = argparse.ArgumentParser(
            description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
        )
        subparsers = parser.add_subparsers(title="subcommands", help="additional help")

        parser_list = subparsers.add_parser(
            "list", aliases=["ls"], help="List your boxes."
        )
        parser_list.set_defaults(func=client.list)

        parser_create = subparsers.add_parser("create", help="Create a box.")
        parser_create.add_argument(
            "image", default="ubuntu18", help="image alias or full AMI id"
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
        parser_create.add_argument("-t", "--instance-type", default="t3.small")
        parser_create.set_defaults(func=client.create)

        parser_delete = subparsers.add_parser("delete", help="Delete a box.")
        parser_delete.add_argument("instance_id")
        parser_delete.set_defaults(func=client.delete)

        parser_ssh = subparsers.add_parser("ssh", help="SSH into a box.")
        parser_ssh.add_argument("box")
        parser_ssh.add_argument("-u", "--ssh-user", default="ubuntu")
        parser_ssh.set_defaults(func=client.ssh)

        args = parser.parse_args(sysargs[1:])
        if args.func(args):
            return 0
        return 86
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
        log.debug(f"fetching boxes for user={self._user!r}")
        for box in self._list_boxes():
            print(f"- {box['name']}:")
            print(
                "    "
                + "\n    ".join(
                    [f"{field}: {box[field]!r}" for field in sorted(box.keys())]
                )
            )
        return True

    def create(self, args):
        self._setup()
        payload = {
            "instance_type": args.instance_type,
        }
        if args.image.startswith("ami-"):
            payload["ami"] = args.image
        else:
            payload["image_alias"] = args.image
        if args.connect:
            payload["connect"] = "1"
        if args.name != "":
            payload["name"] = args.name
        req = self._build_request(
            os.path.join(self._url, "box"),
            data=json.dumps(payload).encode("utf-8"),
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
            if box.get("public_ip") is None:
                log.warning(f"public_ip is has not yet been assigned")
        return True

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
        return True

    def ssh(self, args):
        self._setup()
        boxes = self._list_boxes()
        matching_box = None
        for box in boxes:
            if box.get("name") == args.box or box.get("image_alias") == args.box:
                matching_box = box
                break
        if matching_box is None:
            log.error(f"no box found matching {args.box!r}")
            return False
        sys.stdout.flush()
        sys.stderr.flush()
        os.execvp(
            "ssh", ["ssh", f"{args.ssh_user}@{matching_box.get('public_dns_name')}"]
        )

    def _list_boxes(self):
        req = self._build_request(self._url)
        raw_response = {}
        with self._urlopen(req) as response:
            raw_response = json.load(response)
        return raw_response["boxes"]

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
