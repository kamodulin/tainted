import logging
import os

logger = logging.getLogger("tainted")


def init_logger():
    level = os.environ.get("LOG_LEVEL", "INFO")

    format = "[%(name)s] %(levelname)s: %(message)s"
    if level.upper() == "DEBUG":
        format += " (%(funcName)s:%(lineno)d)"

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(format))

    logger.addHandler(handler)
    logger.setLevel(level)
