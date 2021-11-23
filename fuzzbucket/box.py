import typing
import dataclasses
import datetime

from .tags import Tags
from . import NoneString


@dataclasses.dataclass
class Box:
    created_at: NoneString = None
    image_alias: NoneString = None
    image_id: NoneString = None
    instance_id: NoneString = None
    instance_type: NoneString = None
    key_alias: NoneString = None
    name: NoneString = None
    other_tags: typing.Dict[str, str] = dataclasses.field(default_factory=dict)
    public_dns_name: NoneString = None
    public_ip: NoneString = None
    ttl: int = 0
    user: NoneString = None

    def as_json(self):
        return dict(
            [
                (key, getattr(self, key))
                for key in (list(self.__dict__.keys()) + ["age"])
                if getattr(self, key) is not None
            ]
        )

    @property
    def age(self) -> str:
        if not self.created_at:
            return "?"
        return str(
            datetime.datetime.utcnow()
            - datetime.datetime.fromtimestamp(float(self.created_at))
        )

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

        for tag in instance.get("Tags", []):
            attr, cast = {
                "Name": ["name", str],
                Tags.created_at.value: ["created_at", float],
                Tags.image_alias.value: ["image_alias", str],
                Tags.user.value: ["user", str],
                # NOTE: the `ttl` at this point is expected to be a
                # `str(int)`, but the string coercion of `float`
                # will safely handle both `int` and `float` values,
                # which is why there's a double-casting through
                # `float` and `int` here. Sub-second precision for
                # a `ttl` value can be safely discarded given that
                # the reaping process is typically run on a
                # multiple-minute interval. {{
                Tags.ttl.value: ["ttl", lambda s: int(float(s))],
                # }}
            }.get(tag["Key"], [None, str])
            if attr is not None:
                setattr(box, attr, cast(tag["Value"]))  # type: ignore
                continue

            box.other_tags[str(tag["Key"])] = str(tag["Value"])

        key_alias = box.user
        if instance["KeyName"] != box.user:
            key_alias = instance["KeyName"].replace(f"${box.user}-", "")
        box.key_alias = key_alias
        return box
