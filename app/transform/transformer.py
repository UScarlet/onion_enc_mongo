import logging

from protocol.wire import read_int32, OP_MSG, OP_COMPRESSED
from protocol.compression import (
    parse_op_compressed_wrapper,
    unpack_op_compressed,
    pack_op_compressed,
)
from protocol.op_msg import parse_op_msg, build_op_msg
from logging_tools.inspection import summarize_parsed_op_msg
from transform.layers.transformer_det import (
    transform_client_parsed_op_msg_with_det,
    transform_server_parsed_op_msg_with_det,
)

logger = logging.getLogger("MongoProxy")


def _rebuild_op_msg_from_parsed(parsed: dict) -> bytes:
    """
    Собрать бинарное OP_MSG-сообщение обратно из parsed-структуры.
    """
    return build_op_msg(
        request_id=parsed["header"][0],
        response_to=parsed["header"][1],
        flags=parsed["flags"],
        sections=parsed["sections"],
        checksum=parsed["checksum"],
    )


def transform_message(raw_msg: bytes, direction: str) -> bytes:
    """
    Общая точка входа для преобразования MongoDB-сообщения.

    Сейчас:
    - поддерживается только DET-слой
    - логика DET вынесена в transform/layers/transformer_det.py

    transformer.py отвечает только за:
    - разбор raw-сообщения
    - dispatch по направлению
    - rebuild сообщения
    - работу с OP_COMPRESSED
    """
    try:
        opcode = read_int32(raw_msg, 12)

        # ---------------------------------------
        # Обычный OP_MSG
        # ---------------------------------------
        if opcode == OP_MSG:
            parsed = parse_op_msg(raw_msg)

            if direction == "client->server":
                new_parsed, changed = transform_client_parsed_op_msg_with_det(parsed)
            else:
                new_parsed, changed = transform_server_parsed_op_msg_with_det(parsed)

            if not changed:
                return raw_msg

            rebuilt = _rebuild_op_msg_from_parsed(new_parsed)
            logger.info("TRANSFORMED %s", summarize_parsed_op_msg(new_parsed, direction))
            return rebuilt

        # ---------------------------------------
        # OP_COMPRESSED(inner=OP_MSG)
        # ---------------------------------------
        if opcode == OP_COMPRESSED:
            wrapper = parse_op_compressed_wrapper(raw_msg)
            inner_message = unpack_op_compressed(raw_msg)
            inner_opcode = read_int32(inner_message, 12)

            if inner_opcode != OP_MSG:
                return raw_msg

            parsed = parse_op_msg(inner_message)

            if direction == "client->server":
                new_parsed, changed = transform_client_parsed_op_msg_with_det(parsed)
            else:
                new_parsed, changed = transform_server_parsed_op_msg_with_det(parsed)

            if not changed:
                return raw_msg

            rebuilt_inner = _rebuild_op_msg_from_parsed(new_parsed)
            rebuilt_outer = pack_op_compressed(
                rebuilt_inner,
                compressor_id=wrapper["compressor_id"],
            )

            logger.info("TRANSFORMED %s", summarize_parsed_op_msg(new_parsed, direction))
            return rebuilt_outer

        return raw_msg

    except Exception as e:
        logger.error("transform_message failed, forwarding raw: %s", e)
        return raw_msg