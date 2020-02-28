import sys

from setuptools import setup


def main():
    setup(
        name="boxbot-client",
        version="0.1.0",
        py_modules=["boxbot_client"],
        entry_points={"console_scripts": ["boxbot-client = boxbot_client:main"]},
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
