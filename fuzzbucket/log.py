import logging

from . import cfg


def setup_logging() -> logging.Logger:
    log_levels = cfg.getdict("FUZZBUCKET_LOG_LEVELS")
    log_levels.setdefault(".", "info")
    log_levels.setdefault("fuzzbucket", "info")

    root_log = logging.getLogger()
    log = root_log.getChild("fuzzbucket")

    for log_name, level_name in log_levels.items():
        log_level = getattr(logging, level_name.upper())

        if log_name == ".":
            log.debug(f"setting root logger level={log_level!r}")

            root_log.setLevel(log_level)

            continue

        log.debug(f"setting logger={log_name!r} level={log_level!r}")

        logging.getLogger(log_name).setLevel(log_level)

    return log


log = setup_logging()
