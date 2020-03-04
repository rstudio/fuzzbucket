import datetime

from .tags import Tags


class Box:
    def __init__(self):
        self.created_at = None
        self.image_alias = None
        self.image_id = None
        self.instance_id = None
        self.instance_type = None
        self.name = None
        self.public_dns_name = None
        self.public_ip = None
        self.ttl = None
        self.user = None

    def as_json(self):
        return dict(
            [
                (key, getattr(self, key))
                for key in (list(self.__dict__.keys()) + ["age"])
                if getattr(self, key) is not None
            ]
        )

    @property
    def age(self):
        if not self.created_at:
            return "?"
        delta = datetime.datetime.utcnow() - datetime.datetime.fromtimestamp(
            float(self.created_at)
        )
        hours, remainder = divmod(delta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{delta.days}d{hours}h{minutes}m{seconds}s"

    @classmethod
    def from_dict(cls, as_dict):
        box = cls()
        for key in box.__dict__.keys():
            if key not in as_dict:
                continue
            setattr(box, key, as_dict[key])
        return box

    @classmethod
    def from_ec2_dict(cls, instance):
        box = cls()
        box.instance_id = instance["InstanceId"]
        box.instance_type = instance["InstanceType"]
        box.image_id = instance["ImageId"]
        box.public_dns_name = (
            instance["PublicDnsName"] if instance["PublicDnsName"] != "" else None
        )
        box.public_ip = instance.get("PublicIpAddress", None)
        for tag in instance.get("Tags", []):
            attr, cast = {
                "Name": ["name", str],
                Tags.created_at.value: ["created_at", float],
                Tags.image_alias.value: ["image_alias", str],
                Tags.ttl.value: ["ttl", int],
                Tags.user.value: ["user", str],
            }.get(tag["Key"])
            if attr is not None:
                setattr(box, attr, cast(tag["Value"]))
        return box
