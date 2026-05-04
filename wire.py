import asyncio
import struct
from typing import Tuple, Optional

MSG_HEADER_SIZE = 16

OP_MSG = 2013
OP_COMPRESSED = 2012

FLAG_CHECKSUM_PRESENT = 1 << 0


class ProtocolError(Exception):
    """
    Ошибка структуры MongoDB wire message.
    """
    pass


def read_int32(data: bytes, offset: int) -> int:
    return struct.unpack_from('<i', data, offset)[0]


def read_uint32(data: bytes, offset: int) -> int:
    return struct.unpack_from('<I', data, offset)[0]


def write_int32(value: int) -> bytes:
    return struct.pack('<i', value)


def write_uint32(value: int) -> bytes:
    return struct.pack('<I', value)


async def read_full_message(reader: asyncio.StreamReader) -> Optional[bytes]:
    """
    Прочитать одно полное MongoDB wire-сообщение.
    """
    try:
        header = await reader.readexactly(MSG_HEADER_SIZE)
    except asyncio.IncompleteReadError:
        return None

    msg_len = read_int32(header, 0)
    if msg_len < MSG_HEADER_SIZE:
        raise ProtocolError(f"Invalid message length: {msg_len}")

    try:
        body = await reader.readexactly(msg_len - MSG_HEADER_SIZE)
    except asyncio.IncompleteReadError:
        raise ProtocolError("Connection closed while reading message body")

    return header + body


def read_cstring(data: bytes, offset: int) -> Tuple[str, int]:
    """
    Прочитать cstring: UTF-8 строку, завершённую нулевым байтом.
    """
    end = data.find(b'\x00', offset)
    if end == -1:
        raise ProtocolError("C-string not terminated")
    return data[offset:end].decode('utf-8'), end + 1