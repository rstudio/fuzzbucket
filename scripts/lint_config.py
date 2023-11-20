#!/usr/bin/env python
"""
%(prog)s [options] <config-path>

Lint and optionally modify a given fuzzbucket config file.
"""
import argparse
import difflib
import pathlib
import subprocess
import sys
import typing

import yaml


def main(sysargs: list[str] = sys.argv[:]):
    parser = argparse.ArgumentParser(usage=__doc__)
    parser.add_argument("config_path", type=pathlib.Path)
    parser.add_argument(
        "-w",
        "--write",
        action="store_true",
        help="write back the modified file to the same path",
    )
    parser.add_argument(
        "-d",
        "--diff",
        action="store_true",
        help="output the diff of changes if present",
    )

    args = parser.parse_args(sysargs[1:])
    orig_text = args.config_path.read_text()
    config = yaml.unsafe_load(orig_text)
    new_config = _ensure_migrated(config)
    default_config = _load_default_config()

    for env_var in default_config["environment"].keys():
        value = default_config["environment"][env_var]

        if str(value).strip() != "":
            new_config["environment"].setdefault(env_var, value)

    new_text = yaml.dump(new_config)

    if args.write:
        args.config_path.write_text(new_text)

        return 0

    if not args.diff:
        print(new_text, end="")

        return 0

    any_diff = False

    for line in difflib.unified_diff(
        orig_text.splitlines(False),
        new_text.splitlines(False),
        fromfile=f"a/{args.config_path}",
        tofile=f"b/{args.config_path}",
        lineterm="",
    ):
        print(line, file=sys.stdout)

        any_diff = True

    if any_diff:
        print(f"\n🧱 {args.config_path} needs to change!", file=sys.stderr)

        return 1

    print(f"🍩 {args.config_path} is good!", file=sys.stderr)

    return 0


def _load_default_config() -> dict[str, typing.Any]:
    top = pathlib.Path(
        subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], encoding="utf-8"
        ).strip()
    )
    return yaml.safe_load(top.joinpath("default-config.yml").read_text())


def _ensure_migrated(config: dict[str, typing.Any]) -> dict[str, typing.Any]:
    if "environment" in config:
        return yaml.unsafe_load(yaml.dump(config))

    new_config = _load_default_config()

    for key, env_var in (
        ("allowedGithubOrgs", "FUZZBUCKET_ALLOWED_GITHUB_ORGS"),
        ("awsRegion", "FUZZBUCKET_REGION"),
        ("branding", "FUZZBUCKET_BRANDING"),
        ("defaultImageAlias", "FUZZBUCKET_DEFAULT_IMAGE_ALIAS"),
        ("defaultInstanceTags", "FUZZBUCKET_DEFAULT_INSTANCE_TAGS"),
        ("defaultInstanceType", "FUZZBUCKET_DEFAULT_INSTANCE_TYPE"),
        ("defaultPublicIp", "FUZZBUCKET_DEFAULT_PUBLIC_IP"),
        ("defaultSecurityGroups", "FUZZBUCKET_DEFAULT_SECURITY_GROUPS"),
        ("defaultSubnet", "FUZZBUCKET_DEFAULT_SUBNETS"),
        ("defaultTtl", "FUZZBUCKET_DEFAULT_TTL"),
        ("flaskSecretKey", "FUZZBUCKET_FLASK_SECRET_KEY"),
        ("logLevel", "FUZZBUCKET_LOG_LEVEL"),
        ("rootLogLevel", "FUZZBUCKET_ROOT_LOG_LEVEL"),
    ):
        if key in config:
            new_config["environment"][env_var] = str(config[key])

    if "oauth" in config:
        for key, env_var in (
            ("clientID", "FUZZBUCKET_GITHUB_OAUTH_CLIENT_ID"),
            ("clientSecret", "FUZZBUCKET_GITHUB_OAUTH_CLIENT_SECRET"),
        ):
            if key in config["oauth"]:
                new_config["environment"][env_var] = str(config["oauth"][key])

    return new_config


if __name__ == "__main__":
    sys.exit(main())
