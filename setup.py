import sys

from setuptools import setup


def main():
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
