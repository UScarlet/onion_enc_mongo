import asyncio
import logging

from protocol.wire import read_full_message, ProtocolError
from logging_tools.inspection import inspect_message
from transform.transformer import transform_message

logger = logging.getLogger("MongoProxy")


async def handle_client(client_reader, client_writer, target_host, target_port):
    """
    Обработать одно клиентское соединение.
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

    async def run(self):
        server = await asyncio.start_server(
            lambda r, w: handle_client(r, w, self.target_host, self.target_port),
            self.listen_host,
            self.listen_port
        )
        logger.info(
            f"Proxy listening on {self.listen_host}:{self.listen_port} -> "
            f"{self.target_host}:{self.target_port}"
        )
        async with server:
            await server.serve_forever()