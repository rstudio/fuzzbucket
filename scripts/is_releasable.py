#!/usr/bin/env python
import os
import re
import sys


def main(sysargs: list[str] = sys.argv[:]):
    releasable = re.match(r"^\d+\.\d+\.\d+$", sysargs[1]) is not None
    msg = f"releasable={releasable}".lower()

    with open(os.environ.get("GITHUB_OUTPUT", "/dev/null"), "a+") as out:
        for stream in out, sys.stdout:
            print(msg, file=stream)

    return 0


if __name__ == "__main__":
    sys.exit(main())
