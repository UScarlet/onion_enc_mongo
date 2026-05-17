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
from transform.layers.transformer_hom import (
    transform_client_parsed_op_msg_with_hom,
)
from transform.layers.transformer_hope import (
    transform_client_parsed_op_msg_with_hope,
)
from transform.layers.transformer_hom import transform_client_parsed_op_msg_with_hom
from transform.layers.transformer_hope import transform_client_parsed_op_msg_with_hope # Добавлено
from transform.layers.transformer_det import (
    transform_client_parsed_op_msg_with_det,
    transform_server_parsed_op_msg_with_det,
)

logger = logging.getLogger("MongoProxy")


def _rebuild_op_msg_from_parsed(parsed: dict) -> bytes:
    return build_op_msg(
        request_id=parsed["header"][0],
        response_to=parsed["header"][1],
        flags=parsed["flags"],
        sections=parsed["sections"],
        checksum=parsed["checksum"],
    )


def _apply_client_layers(parsed: dict) -> tuple[dict, bool]:
    """
    Порядок слоёв для client->server:
    1. HOM augment (добавляет поля __hom)
    2. HOPE augment (добавляет поля __hope)
    3. DET rewrite (переписывает оригинальные поля и условия поиска)
    
    Аугментирующие слои (HOM и HOPE) должны отрабатывать ДО DET-слоя, 
    так как DET-слой затирает оригинальный открытый текст.
    """
    changed_any = False
    current = parsed

    # 1. Применяем слой HOM
    current, changed_hom = transform_client_parsed_op_msg_with_hom(current)
    changed_any = changed_any or changed_hom

    # 2. Применяем слой HOPE
    current, changed_hope = transform_client_parsed_op_msg_with_hope(current)
    changed_any = changed_any or changed_hope

    # 3. Применяем слой DET
    current, changed_det = transform_client_parsed_op_msg_with_det(current)
    changed_any = changed_any or changed_det

    return current, changed_any

def transform_message(raw_msg: bytes, direction: str) -> bytes:
    try:
        opcode = read_int32(raw_msg, 12)

        # ---------------------------------------
        # Обычный OP_MSG
        # ---------------------------------------
        if opcode == OP_MSG:
            parsed = parse_op_msg(raw_msg)

            if direction == "client->server":
                new_parsed, changed = _apply_client_layers(parsed)
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
                new_parsed, changed = _apply_client_layers(parsed)
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