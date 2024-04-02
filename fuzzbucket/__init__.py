import functools
import typing

import flask

from . import aws


def deferred_app(
    environ: dict[str, str], start_response: typing.Callable
) -> typing.Iterable[bytes]:
    return cached_app()(environ, start_response)


@functools.cache
def cached_app() -> flask.Flask:
    preflight_check()

    from .app import create_app

    return create_app()


def deferred_reap_boxes(event, context):
    return cached_reap_boxes()(event, context)


@functools.cache
def cached_reap_boxes() -> typing.Callable:
    preflight_check()

    from .reaper import reap_boxes

    return reap_boxes


def preflight_check():
    assert (
        aws.get_vpc_id(aws.get_ec2_client()) is not None
    ), "Missing or invalid `FUZZBUCKET_DEFAULT_VPC`"
