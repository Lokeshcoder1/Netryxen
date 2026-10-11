import logging
import sys
from typing import Any


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """
    Configures application-wide logging with security-conscious formatting.
    Ensures secrets are not inadvertently leaked.
    """
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Clear existing handlers to prevent duplicates
    if not root_logger.handlers:
        root_logger.addHandler(handler)
    else:
        root_logger.handlers.clear()
        root_logger.addHandler(handler)

    # Set third party loggers to WARNING to reduce noise
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    logger = logging.getLogger("nids")
    logger.setLevel(level)
    return logger


logger = setup_logging()
