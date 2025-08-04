import logging

from dependencies import get_kite_client

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)


if __name__ == "__main__":
    holdings = get_kite_client().holdings()
    logger.info("Fetched Holdings: %s", holdings)