import typing

import flask
import flask.json.provider


class AsJSONProvider(flask.json.provider.DefaultJSONProvider):
    @staticmethod
    def default(o: typing.Any) -> typing.Any:
        if hasattr(o, "as_json") and callable(o.as_json):
            return o.as_json()

        if hasattr(o, "__dict__"):
            return o.__dict__

        return flask.json.provider.DefaultJSONProvider.default(o)  # pragma: no cover
