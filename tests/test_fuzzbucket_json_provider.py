from fuzzbucket import json_provider


def test_json_provider(app):
    class WithAsJson:
        def as_json(self):
            return {"golden": "feelings"}

    class Dictish:
        def __init__(self):
            self.mellow = "gold"

    other = ("odelay", ["mut", "ati", "ons"])

    def enc(thing):
        return json_provider.AsJSONProvider(app).dumps(thing)

    assert enc(WithAsJson()) == '{"golden": "feelings"}'
    assert enc(Dictish()) == '{"mellow": "gold"}'
    assert enc(other) == '["odelay", ["mut", "ati", "ons"]]'
