import argparse
import os
import sys

from collections import namedtuple

SearchEntry = namedtuple("SearchEntry", ("alias", "owner", "name"))

CANONICAL_ID = "099720109477"
MARKETPLACE_ID = "679593333241"
RHEL_ID = "309956199498"
ALIAS_SEARCHES = [
    SearchEntry(
        "ubuntu18",
        CANONICAL_ID,
        "ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*",
    ),
    SearchEntry(
        "ubuntu16",
        CANONICAL_ID,
        "ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server-*",
    ),
    # TODO: find a supported (??) centos6 image
    # SearchEntry("centos6", MARKETPLACE_ID, "CentOS Linux 6 x86_64 HVM EBS*"),
    # TODO: find a supported (??) centos7 image
    # SearchEntry("centos7", MARKETPLACE_ID, "CentOS Linux 7 x86_64 HVM EBS*"),
    SearchEntry("centos8", MARKETPLACE_ID, "CentOS-8-x86_64-EBS-HVM-*"),
    SearchEntry("rhel6", RHEL_ID, "RHEL-6.10_HVM_*-x86_64-*"),
    SearchEntry("rhel7", RHEL_ID, "RHEL-7.8_HVM_*-x86_64-*"),
    SearchEntry("rhel8", RHEL_ID, "RHEL-8.2.0_HVM_*-x86_64-*"),
]


def main(sysargs=sys.argv[:]):
    parser = argparse.ArgumentParser()
    parser.add_argument("outfile", type=os.path.realpath)

    args = parser.parse_args(sysargs[1:])

    import boto3

    client = boto3.client("ec2")
    image_aliases = {}
    for search in ALIAS_SEARCHES:
        response = client.describe_images(
            Filters=[dict(Name="name", Values=[search.name])], Owners=[search.owner]
        )
        sorted_images = list(
            sorted(response["Images"], key=lambda i: i["CreationDate"])
        )
        if len(sorted_images) == 0:
            raise RuntimeError(f"no images found for search={search}")
        image_aliases[search.alias] = sorted_images[-1]["ImageId"]

    if os.path.basename(args.outfile) == "-":
        print(f"image_aliases = {repr(image_aliases)}")
        return 0

    with open(args.outfile, "w") as out:
        out.write(f"image_aliases = {repr(image_aliases)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
