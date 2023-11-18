import logging
import typing

import fuzzbucket.cfg as cfg

ROOT_LOG = logging.getLogger()
log = ROOT_LOG.getChild("fuzzbucket")

LOG_LEVEL = getattr(
    logging, typing.cast(str, cfg.get("FUZZBUCKET_LOG_LEVEL", default="info")).upper()
)
log.setLevel(LOG_LEVEL)

ROOT_LOG_LEVEL = getattr(
    logging,
    typing.cast(str, cfg.get("FUZZBUCKET_ROOT_LOG_LEVEL", default="info")).upper(),
)
ROOT_LOG.setLevel(ROOT_LOG_LEVEL)
