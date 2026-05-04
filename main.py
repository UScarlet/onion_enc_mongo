import asyncio
import logging

from proxy import MongoProxy

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("MongoProxy")


if __name__ == '__main__':
    proxy = MongoProxy()
    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        logger.info("Shutting down")