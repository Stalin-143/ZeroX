import logging
import argparse

def setup_logger():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args, _ = parser.parse_known_args()

    logger = logging.getLogger("Zerox")
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logger()