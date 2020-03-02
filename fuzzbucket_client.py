#!/usr/bin/env python3
"""
A client for fuzzbucket.

Configuration is accepted via the following environment variables:

    FUZZBUCKET_URL - string URL of the fuzzbucket instance including path prefix
    FUZZBUCKET_CREDENTIALS - "github-user:fuzzbucket-token" string

"""
import argparse
import configparser
import contextlib
import base64
import io
import json
import logging
import os
import sys
import urllib.parse
import urllib.request

log = logging.getLogger("fuzzbucket")
logging.basicConfig(
    stream=sys.stdout,
    style="{",
    format="# {name}:{levelname}:{asctime}:: {message}",
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

        parser_list_aliases = subparsers.add_parser(
            "list-aliases", aliases=["la"], help="List known image aliases."
        )
        parser_list_aliases.set_defaults(func=client.list_aliases)

        parser_create = subparsers.add_parser(
            "create", aliases=["new"], help="Create a box."
        )
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
        parser_create.add_argument(
            "-T",
            "--ttl",
            default=str(3600 * 4),
            help="set the TTL for the box, after which it will be reaped",
        )
        parser_create.add_argument("-t", "--instance-type", default="t3.small")
        parser_create.set_defaults(func=client.create)

        parser_delete = subparsers.add_parser(
            "delete", aliases=["rm"], help="Delete a box."
        )
        parser_delete.add_argument("box")
        parser_delete.set_defaults(func=client.delete)

        parser_reboot = subparsers.add_parser(
            "reboot", aliases=["restart"], help="Reboot a box."
        )
        parser_reboot.add_argument("box")
        parser_reboot.set_defaults(func=client.reboot)

        parser_ssh = subparsers.add_parser("ssh", help="SSH into a box.")
        parser_ssh.add_argument("box")
        parser_ssh.add_argument("-u", "--ssh-user", default="")
        parser_ssh.set_defaults(func=client.ssh)

        known_args, unknown_args = parser.parse_known_args(sysargs[1:])
        if known_args.func(known_args, unknown_args):
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

    def list(self, *_):
        self._setup()
        log.debug(f"fetching boxes for user={self._user!r}")
        boxes = self._list_boxes()
        log.info(f"fetched boxes for user={self._user!r} count={len(boxes)}")
        print(self._boxes_to_ini(boxes), end="")
        return True

    def list_aliases(self, *_):
        self._setup()
        req = self._build_request(os.path.join(self._url, "aliases"))
        raw_response = {}
        with self._urlopen(req) as response:
            raw_response = json.load(response)
        if "image_aliases" not in raw_response:
            log.error("failed to fetch image aliases")
            return False
        print(self._image_aliases_to_ini(raw_response["image_aliases"]), end="")
        return True

    def create(self, known_args, _):
        self._setup()
        payload = {
            "instance_type": known_args.instance_type,
            "ttl": known_args.ttl,
        }
        if known_args.image.startswith("ami-"):
            payload["ami"] = known_args.image
        else:
            payload["image_alias"] = known_args.image
        if known_args.connect:
            payload["connect"] = "1"
        if known_args.name != "":
            payload["name"] = known_args.name
        req = self._build_request(
            os.path.join(self._url, "box"),
            data=json.dumps(payload).encode("utf-8"),
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

        print(self._boxes_to_ini(raw_response["boxes"]), end="")
        return True

    def delete(self, known_args, _):
        self._setup()
        matching_box = self._find_box(known_args.box)
        if matching_box is None:
            log.error(f"no box found matching {known_args.box!r}")
            return False
        req = self._build_request(
            os.path.join(self._url, "box", matching_box["instance_id"]), method="DELETE"
        )
        with self._urlopen(req) as response:
            _ = response.read()
        log.info(f"deleted box for user={self._user!r} name={matching_box['name']}")
        print(self._boxes_to_ini([matching_box]), end="")
        return True

    def reboot(self, known_args, _):
        self._setup()
        matching_box = self._find_box(known_args.box)
        if matching_box is None:
            log.error(f"no box found matching {known_args.box!r}")
            return False
        req = self._build_request(
            os.path.join(self._url, "reboot", matching_box["instance_id"]),
            method="POST",
        )
        with self._urlopen(req) as response:
            _ = response.read()
        log.info(f"rebooted box for user={self._user!r} box={matching_box['name']!r}")
        print(self._boxes_to_ini([matching_box]), end="")
        return True

    def ssh(self, known_args, unknown_args):
        self._setup()
        matching_box = self._find_box(known_args.box)
        if matching_box is None:
            log.error(f"no box found matching {known_args.box!r}")
            return False
        if known_args.ssh_user == "":
            known_args.ssh_user = self._guess_ssh_user(
                matching_box["image_alias"], "ec2-user"
            )
        log.info(
            f"ssh'ing into matching_box={matching_box['name']!r} "
            + f"ssh_user={known_args.ssh_user!r}"
        )
        print(self._boxes_to_ini([matching_box]), end="")
        sys.stdout.flush()
        sys.stderr.flush()
        os.execvp(
            "ssh",
            ["ssh", f"{known_args.ssh_user}@{matching_box.get('public_dns_name')}"]
            + unknown_args,
        )
        return True

    def _find_box(self, box_search):
        boxes = self._list_boxes()
        for box in boxes:
            log.debug(f"finding box_search={box_search!r} considering box={box!r}")
            if box.get("name") == box_search or box.get("image_alias") == box_search:
                return box
        return None

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
        return self._env.get("FUZZBUCKET_URL")

    @property
    def _credentials(self):
        return self._env.get("FUZZBUCKET_CREDENTIALS")

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

    @staticmethod
    def _boxes_to_ini(boxes):
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

    @staticmethod
    def _image_aliases_to_ini(image_aliases):
        image_aliases_ini = configparser.ConfigParser()
        image_aliases_ini.add_section("image_aliases")
        for alias, ami in sorted(image_aliases.items()):
            image_aliases_ini.set("image_aliases", alias, ami)
        buf = io.StringIO()
        image_aliases_ini.write(buf)
        buf.seek(0)
        return buf.read()

    @staticmethod
    def _guess_ssh_user(image_alias, default="root"):
        image_alias = image_alias.lower()
        if image_alias.startswith("ubuntu"):
            return "ubuntu"
        if image_alias.startswith("centos"):
            return "centos"
        if image_alias.startswith("rhel") or image_alias.startswith("suse"):
            return "ec2-user"
        return default


if __name__ == "__main__":
    sys.exit(main())
