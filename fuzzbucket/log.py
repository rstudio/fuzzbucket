import logging

import aws_lambda_powertools

from . import cfg


def setup_logging() -> aws_lambda_powertools.Logger:
    log_levels = cfg.getdict("FUZZBUCKET_LOG_LEVELS")
    log_levels.setdefault(".", "info")

    root_log = logging.getLogger()
    log = aws_lambda_powertools.Logger()

    for log_name, level_name in log_levels.items():
        log_level = getattr(logging, level_name.upper())

        if log_name == ".":
            log.debug("setting root logger level", extra=dict(level=log_level))

            root_log.setLevel(log_level)

            continue

        log.debug("setting logger", extra=dict(log_name=log_name, level=log_level))

        logging.getLogger(log_name).setLevel(log_level)

    return log


log = setup_logging()
