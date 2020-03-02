import sys

from setuptools import setup


def main():
    setup(
        name="fuzzbucket-client",
        version="0.1.0",
        py_modules=["fuzzbucket_client"],
        entry_points={
            "console_scripts": ["fuzzbucket-client = fuzzbucket_client:main"]
        },
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
