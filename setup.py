from __future__ import print_function

import sys

from setuptools import setup


def main():
    if sys.version_info[:2] < (3, 5):
        print("ERROR: fuzzbucket-client requires python 3.5+")
        print("This python is:")
        print(sys.version)
        return 86

    from fuzzbucket_client import full_version

    setup(
        name="fuzzbucket-client",
        version=full_version(),
        py_modules=["fuzzbucket_client"],
        python_requires=">3.5,<4",
        entry_points={
            "console_scripts": ["fuzzbucket-client = fuzzbucket_client:main"]
        },
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
