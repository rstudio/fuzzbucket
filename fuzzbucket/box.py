import dataclasses
import datetime
import typing

from . import datetime_ext, tags


@dataclasses.dataclass
class Box:
    created_at: str | None = None
    image_alias: str | None = None
    image_id: str | None = None
    instance_id: str | None = None
    instance_type: str | None = None
    key_alias: str | None = None
    name: str | None = None
    other_tags: dict[str, str] | None = None
    public_dns_name: str | None = None
    public_ip: str | None = None
    region: str | None = None
    ttl: int | None = None
    user: str | None = None

    def as_json(self):
        return self.__dict__.copy() | {"age": self.age, "max_age": self.max_age}

    @property
    def age(self) -> str | None:
        if self.created_at is None:
            return None

        return str(
            datetime_ext.utcnow()
            - datetime.datetime.fromtimestamp(float(self.created_at))
        )

    @property
    def max_age(self) -> str | None:
        if self.ttl is None:
            return None

        return str(datetime.timedelta(seconds=self.ttl))

    @classmethod
    def from_ec2_dict(cls, instance: dict) -> "Box":
        box = cls(
            instance_id=instance["InstanceId"],
            instance_type=instance["InstanceType"],
            image_id=instance["ImageId"],
            other_tags={},
            public_dns_name=(
                instance["PublicDnsName"] if instance["PublicDnsName"] != "" else None
            ),
            public_ip=instance.get("PublicIpAddress", None),
        )

        az = instance.get("Placement", {}).get("AvailabilityZone")
        if az is not None:
            box.region = str(az[:-1])

        for tag in instance.get("Tags", []):
            attr, cast = {
                "Name": ("name", str),
                tags.Tags.created_at.value: ("created_at", float),
                tags.Tags.image_alias.value: ("image_alias", str),
                tags.Tags.user.value: ("user", str),
                # NOTE: the `ttl` at this point is expected to be a
                # `str(int)`, but the string coercion of `float`
                # will safely handle both `int` and `float` values,
                # which is why there's a double-casting through
                # `float` and `int` here. Sub-second precision for
                # a `ttl` value can be safely discarded given that
                # the reaping process is typically run on a
                # multiple-minute interval. {{
                tags.Tags.ttl.value: ("ttl", lambda s: int(float(s))),
                # }}
            }.get(tag["Key"], (None, str))

            if attr is not None:
                setattr(box, attr, cast(tag["Value"]))  # type: ignore
                continue

            assert box.other_tags is not None

            box.other_tags[str(tag["Key"])] = str(tag["Value"])

        key_alias = box.user
        if instance["KeyName"] != box.user:
            key_alias = instance["KeyName"].replace(f"{box.user}-", "")

        box.key_alias = key_alias

        return box
