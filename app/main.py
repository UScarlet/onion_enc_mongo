import asyncio
import logging
import os
from proxy.proxy import MongoProxy

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("MongoProxy")


if __name__ == '__main__':
    # Читаем все переменные из окружения
    # .get(key, default) - если переменной нет в .env, возьмет значение по умолчанию
    listen_host = os.getenv('PROXY_LISTEN_HOST', '0.0.0.0')
    listen_port = int(os.getenv('PROXY_LISTEN_PORT', 27018))
    target_host = os.getenv('MONGO_TARGET_HOST', 'localhost')
    target_port = int(os.getenv('MONGO_TARGET_PORT', 27017))

    # Передаем всё в класс
    proxy = MongoProxy(
        listen_host=listen_host,
        listen_port=listen_port,
        target_host=target_host,
        target_port=target_port
    )

    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        logger.info("Shutting down")