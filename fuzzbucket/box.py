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
    name: NoneString = None
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
        delta = datetime.datetime.utcnow() - datetime.datetime.fromtimestamp(
            float(self.created_at)
        )
        hours, remainder = divmod(delta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{delta.days}d{hours}h{minutes}m{seconds}s"

    @classmethod
    def from_ec2_dict(cls, instance: dict) -> "Box":
        box = cls(
            instance_id=instance["InstanceId"],
            instance_type=instance["InstanceType"],
            image_id=instance["ImageId"],
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
                Tags.ttl.value: ["ttl", int],
                Tags.user.value: ["user", str],
            }.get(tag["Key"], [None, str])
            if attr is not None:
                setattr(box, attr, cast(tag["Value"]))  # type: ignore
        return box
