import asyncio
import logging
from functools import partial

from protocol.wire import read_full_message, ProtocolError
from logging_tools.inspection import inspect_message
from transform.transformer import transform_message

logger = logging.getLogger("MongoProxy")


async def handle_client(client_reader, client_writer, target_host, target_port):
    
    """
    Обработать одно клиентское соединение.
    target - СУБД, mongodb_server
    client - либо vscode, либо mongodb_compass
    
    клиентов на одном порту может быть много. Mongodb атомарные операции - она справится
    но поддержку такого функционала надо сделать - поэтому async функции
    """
    addr = client_writer.get_extra_info('peername')
    logger.info(f"New connection from {addr}")

    try:
        target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
    except Exception as e:
        logger.error(f"Cannot connect to target MongoDB: {e}")
        client_writer.close()
        await client_writer.wait_closed()
        return

    # трафик от клиента к субд-серверу через прокси
    #TODO тут шифрование
    async def forward_to_target():
        while True:
            try:
                raw_msg = await read_full_message(client_reader)
                if raw_msg is None:
                    break

                inspect_message(raw_msg, "client->server", str(addr))
                outgoing_msg = transform_message(raw_msg, "client->server")

                target_writer.write(outgoing_msg)
                await target_writer.drain()

            except ProtocolError as e:
                logger.error(f"Protocol error in forward_to_target: {e}")
                break
            except ConnectionError:
                break
            except Exception as e:
                logger.exception(f"Unexpected error in forward_to_target: {e}")
                break


    # трафик от субд-сервера к клиенту через прокси
    #TODO тут расшифрование, но пока заглушка
    # мы работаем с зашифрованными данными
    # но для клиента то их надо расшифровать в читаемый вид
    async def forward_to_client():
        while True:
            try:
                raw_msg = await read_full_message(target_reader)
                if raw_msg is None:
                    break

                inspect_message(raw_msg, "server->client", str(addr))

                client_writer.write(raw_msg)
                await client_writer.drain()

            except ProtocolError as e:
                logger.error(f"Protocol error in forward_to_client: {e}")
                break
            except ConnectionError:
                break
            except Exception as e:
                logger.exception(f"Error in forward_to_client: {e}")
                break


    task_c_to_s = asyncio.create_task(forward_to_target())
    task_s_to_c = asyncio.create_task(forward_to_client())

    await asyncio.wait(
        [task_c_to_s, task_s_to_c],
        return_when=asyncio.FIRST_COMPLETED
    )

    for task in (task_c_to_s, task_s_to_c):
        if not task.done():
            task.cancel()

    client_writer.close()
    target_writer.close()

    await asyncio.gather(
        client_writer.wait_closed(),
        target_writer.wait_closed(),
        return_exceptions=True
    )

    logger.info(f"Connection closed for {addr}")


class MongoProxy:
    """
    В разработке принято разделять понятия:
    Секреты (Credentials): Пароли, токены, ключи шифрования. Никогда не хранятся в коде. Они обязаны быть только в .env или переменных окружения.
    Конфигурация (Settings): Хосты, порты, лимиты. Хранить их как значения по умолчанию в __init__ — это нормально. Это гарантирует, что программа будет работать сразу после скачивания кода.

    еще хочется 1 раз читать конфиг, а не лезть туда каждый раз при открытии новых соединений для того чтобы посмотреть какой порт - поэтому в handle_client не читаем таргеты, а работаем с адаптером
    """
    def __init__(
        self,
        listen_host='0.0.0.0',
        listen_port=27018,
        target_host='localhost',
        target_port=27017
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port


    """
    в D:\Python\InsPy\Lib\asyncio\streams.py
    функция start_server пишет:
    Start a socket server, call back for each client connected.
    The first parameter, `client_connected_cb`, takes two parameters:
    client_reader, client_writer.  client_reader is a StreamReader
    object, while client_writer is a StreamWriter object.  This
    parameter can either be a plain callback function or a coroutine;
    if it is a coroutine, it will be automatically converted into a Task.
    
    1) нужно 2 аргумента в асинкио, а у нас 4 - поэтому адаптер лямбда:
        lambda r, w: handle_client(...)
    2) подать можно и объект корутины - мы это и делаем - его возвращает лямбда
    """

    async def run(self):

        # server = await asyncio.start_server(
        #     lambda r, w: handle_client(r, w, self.target_host, self.target_port),
        #     self.listen_host,
        #     self.listen_port
        # )
        # для читаемости Создаем частичную функцию (адаптер), 
        # которая 'запоминает' host и port, и при вызове добавит их к r и w

        handler = partial(
            handle_client, 
            target_host=self.target_host, 
            target_port=self.target_port
        )
        
        server = await asyncio.start_server(
            handler,
            self.listen_host,
            self.listen_port
        )

        logger.info(
            f"Proxy listening on {self.listen_host}:{self.listen_port} -> "
            f"{self.target_host}:{self.target_port}"
        )
        async with server:
            # Бесконечный цикл, который заставляет программу постоянно слушать указанный порт и принимать входящие соединения от клиентов. Пока выполняется эта строка, сервер работает непрерывно.
            await server.serve_forever()