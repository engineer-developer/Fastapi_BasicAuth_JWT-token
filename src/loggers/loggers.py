import logging

logging.basicConfig(level=logging.DEBUG)


logger = logging.getLogger(name="logger")

formatter = logging.Formatter(
    fmt="%(levelname)s | %(name)s | %(module)s | %(funcName)s | %(message)s",
)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
stream_handler.setLevel(logging.DEBUG)

logger.addHandler(stream_handler)
logger.propagate = False
