from __future__ import print_function

import distutils.cmd
import distutils.log
import os
import re
import sys
import typing

from setuptools import setup


class IsReleasableCommand(distutils.cmd.Command):
    description: str = "determine if current version is releasable"
    user_options: typing.List[
        typing.Tuple[typing.Optional[str], typing.Optional[str], str]
    ] = []

    def initialize_options(self):
        ...

    def finalize_options(self):
        ...

    def run(self):
        from fuzzbucket_client import full_version

        value = full_version()
        releasable = re.match("^[0-9]+\\.[0-9]+\\.[0-9]+$", value) is not None
        self.announce(
            f"Version {value} is {'' if releasable else 'NOT '}releasable",
            level=distutils.log.INFO,
        )
        if os.getenv("GITHUB_ACTIONS") != "true":
            return
        print(f"::set-output name=releasable::{'true' if releasable else 'false'}")


def main():
    if sys.version_info[:2] < (3, 5):
        print("ERROR: fuzzbucket-client requires python 3.5+")
        print("This python is:")
        print(sys.version)
        return 86

    from fuzzbucket_client import full_version

    setup(
        author="RStudio Connect Engineers",
        author_email="rsc-dev+fuzzbucket@rstudio.com",
        cmdclass={"is_releasable": IsReleasableCommand},
        entry_points={
            "console_scripts": ["fuzzbucket-client = fuzzbucket_client:main"]
        },
        license="MIT",
        name="fuzzbucket-client",
        py_modules=["fuzzbucket_client"],
        python_requires=">3.5,<4",
        url="https://github.com/rstudio/fuzzbucket",
        version=full_version(),
        zip_safe=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
