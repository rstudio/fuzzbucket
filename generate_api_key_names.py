import argparse
import json
import os
import sys
import urllib.request


def main(sysargs=sys.argv[:]):
    parser = argparse.ArgumentParser()
    parser.add_argument("github_org")
    parser.add_argument("github_team")
    parser.add_argument("outfile", type=os.path.realpath)
    parser.add_argument("-u", "--github-api-url", default="https://api.github.com")
    parser.add_argument(
        "-t",
        "--github-token",
        default=os.environ.get("GITHUB_TOKEN"),
        help="GitHub personal access token (also accepted via $GITHUB_TOKEN)",
    )
    args = parser.parse_args(sysargs[1:])

    req = urllib.request.Request(
        os.path.join(
            args.github_api_url,
            "orgs",
            args.github_org,
            "teams",
            args.github_team,
            "members",
        )
    )
    req.headers["Accept"] = "application/vnd.github.v3+json"
    req.headers["Authorization"] = f"token {args.github_token}"
    raw_response = []
    with urllib.request.urlopen(req) as response:
        raw_response = json.load(response)

    body = "apiKeys:\n"
    for login in sorted([member["login"].lower() for member in raw_response]):
        body += f"- {login}\n"

    if os.path.basename(args.outfile) == "-":
        print(body)

    with open(args.outfile, "w") as out:
        out.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
