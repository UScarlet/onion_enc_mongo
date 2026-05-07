import logging

from protocol.wire import read_int32, OP_MSG, OP_COMPRESSED
from protocol.compression import unpack_op_compressed
from protocol.op_msg import parse_op_msg
from logging_tools.inspect_config import INSPECTOR_MODE

logger = logging.getLogger("MongoProxy")

if INSPECTOR_MODE == "verbose":
    from logging_tools.big_inspector import summarize_parsed_op_msg
elif INSPECTOR_MODE == "summary":
    from logging_tools.small_inspector import summarize_parsed_op_msg
else:
    raise ValueError(
        f"Unknown INSPECTOR_MODE={INSPECTOR_MODE!r}. "
        f"Use 'verbose' or 'summary'."
    )


def inspect_message(raw_msg: bytes, direction: str, peer_label: str = "") -> None:
    """
    Общая функция инспекции сообщения.

    Она одна для всех режимов.
    Отличается только summarize_parsed_op_msg, который выбирается
    по INSPECTOR_MODE.
    """
    try:
        opcode = read_int32(raw_msg, 12)

        inspected_msg = raw_msg
        transport_label = "OP_MSG"

        if opcode == OP_COMPRESSED:
            inspected_msg = unpack_op_compressed(raw_msg)
            inner_opcode = read_int32(inspected_msg, 12)
            transport_label = f"OP_COMPRESSED(inner={inner_opcode})"

            if inner_opcode != OP_MSG:
                logger.debug(
                    "%s %s %s: inner opcode is not OP_MSG, skipping parse",
                    direction, peer_label, transport_label
                )
                return

        elif opcode != OP_MSG:
            logger.debug(
                "%s %s opcode=%s: unsupported for parsing, forwarding raw",
                direction, peer_label, opcode
            )
            return

        parsed = parse_op_msg(inspected_msg)
        summary = summarize_parsed_op_msg(parsed, direction)
        if INSPECTOR_MODE == "verbose":
            logger.info("%s\nvia %s\n", summary, transport_label)
        elif INSPECTOR_MODE == "summary":
            logger.info("%s\n", summary)

    except Exception as e:
        logger.error("inspect_message failed (%s %s): %s", direction, peer_label, e)