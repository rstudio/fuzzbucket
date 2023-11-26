import typing

from . import aws


def deferred_app(
    environ: dict[str, str], start_response: typing.Callable
) -> typing.Iterable[str]:
    preflight_check()

    from .app import create_app

    return create_app()(environ, start_response)


def deferred_reap_boxes(event, context):
    preflight_check()

    from .reaper import reap_boxes

    return reap_boxes(event, context)


def preflight_check():
    assert (
        aws.get_vpc_id(aws.get_ec2_client()) is not None
    ), "Missing or invalid `FUZZBUCKET_DEFAULT_VPC`"
