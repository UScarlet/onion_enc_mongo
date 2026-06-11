import logging
from typing import Tuple

from bson import decode, encode

from logging_tools.inspection import (
    ENABLE_DEMO_REWRITE,
    DEMO_REWRITE_FIELD,
    DEMO_REWRITE_FROM,
    DEMO_REWRITE_TO,
)
from protocol.wire import read_int32, OP_MSG, OP_COMPRESSED, FLAG_CHECKSUM_PRESENT
from protocol.compression import (
    parse_op_compressed_wrapper,
    unpack_op_compressed,
    pack_op_compressed,
)
from protocol.op_msg import (
    parse_op_msg,
    build_op_msg,
    get_first_document,
)
from logging_tools.inspection import summarize_parsed_op_msg

logger = logging.getLogger("MongoProxy")


def _rewrite_doc_field_equals(doc: dict, field_name: str, old_value, new_value) -> Tuple[dict, bool]:
    if doc.get(field_name) == old_value:
        new_doc = dict(doc)
        new_doc[field_name] = new_value
        return new_doc, True
    return doc, False


def apply_demo_rewrite_to_parsed_op_msg(parsed: dict) -> Tuple[dict, bool]:
    """
    Демонстрационное изменение OP_MSG.
    Нужна как подготовка к будущему шифрованию.
    """
    if not ENABLE_DEMO_REWRITE:
        return parsed, False

    if parsed['flags'] & FLAG_CHECKSUM_PRESENT:
        logger.warning("Demo rewrite skipped: OP_MSG has checksumPresent")
        return parsed, False

    first_doc = get_first_document(parsed['sections'])
    command_name = next(iter(first_doc.keys()), None) if first_doc else None
    if not command_name:
        return parsed, False

    changed = False
    new_sections = []

    if command_name == "insert":
        for sec in parsed['sections']:
            if sec['type'] == 1 and sec.get('identifier') == "documents":
                new_docs = []
                for raw_doc in sec['documents']:
                    doc = decode(raw_doc)
                    doc, doc_changed = _rewrite_doc_field_equals(
                        doc,
                        DEMO_REWRITE_FIELD,
                        DEMO_REWRITE_FROM,
                        DEMO_REWRITE_TO
                    )
                    changed = changed or doc_changed
                    new_docs.append(encode(doc))

                new_sections.append({
                    'type': 1,
                    'identifier': sec['identifier'],
                    'documents': new_docs
                })
            else:
                new_sections.append(sec)

    elif command_name == "find":
        for sec in parsed['sections']:
            if sec['type'] == 0:
                body_doc = decode(sec['document'])
                filter_doc = body_doc.get("filter")

                if isinstance(filter_doc, dict):
                    new_filter, filter_changed = _rewrite_doc_field_equals(
                        filter_doc,
                        DEMO_REWRITE_FIELD,
                        DEMO_REWRITE_FROM,
                        DEMO_REWRITE_TO
                    )
                    if filter_changed:
                        body_doc = dict(body_doc)
                        body_doc["filter"] = new_filter
                        changed = True

                new_sections.append({
                    'type': 0,
                    'document': encode(body_doc)
                })
            else:
                new_sections.append(sec)

    elif command_name == "delete":
        for sec in parsed['sections']:
            if sec['type'] == 1 and sec.get('identifier') == "deletes":
                new_docs = []

                for raw_doc in sec['documents']:
                    delete_spec = decode(raw_doc)
                    q_doc = delete_spec.get("q")

                    if isinstance(q_doc, dict):
                        new_q, q_changed = _rewrite_doc_field_equals(
                            q_doc,
                            DEMO_REWRITE_FIELD,
                            DEMO_REWRITE_FROM,
                            DEMO_REWRITE_TO
                        )
                        if q_changed:
                            delete_spec = dict(delete_spec)
                            delete_spec["q"] = new_q
                            changed = True

                    new_docs.append(encode(delete_spec))

                new_sections.append({
                    'type': 1,
                    'identifier': sec['identifier'],
                    'documents': new_docs
                })
            else:
                new_sections.append(sec)

    else:
        return parsed, False

    if not changed:
        return parsed, False

    rebuilt_parsed = {
        'header': parsed['header'],
        'flags': parsed['flags'],
        'sections': new_sections,
        'checksum': parsed['checksum'],
        'raw_message': parsed['raw_message'],
    }
    return rebuilt_parsed, True


def transform_message(raw_msg: bytes, direction: str) -> bytes:
    """
    Потенциально изменить MongoDB-сообщение перед отправкой.
    """
    if direction != "client->server":
        return raw_msg

    try:
        opcode = read_int32(raw_msg, 12)

        if opcode == OP_MSG:
            parsed = parse_op_msg(raw_msg)
            new_parsed, changed = apply_demo_rewrite_to_parsed_op_msg(parsed)

            if not changed:
                return raw_msg

            rebuilt = build_op_msg(
                request_id=new_parsed['header'][0],
                response_to=new_parsed['header'][1],
                flags=new_parsed['flags'],
                sections=new_parsed['sections'],
                checksum=new_parsed['checksum'],
            )

            logger.info("TRANSFORMED %s", summarize_parsed_op_msg(new_parsed, "client->server"))
            return rebuilt

        if opcode == OP_COMPRESSED:
            wrapper = parse_op_compressed_wrapper(raw_msg)
            inner_message = unpack_op_compressed(raw_msg)
            inner_opcode = read_int32(inner_message, 12)

            if inner_opcode != OP_MSG:
                return raw_msg

            parsed = parse_op_msg(inner_message)
            new_parsed, changed = apply_demo_rewrite_to_parsed_op_msg(parsed)

            if not changed:
                return raw_msg

            rebuilt_inner = build_op_msg(
                request_id=new_parsed['header'][0],
                response_to=new_parsed['header'][1],
                flags=new_parsed['flags'],
                sections=new_parsed['sections'],
                checksum=new_parsed['checksum'],
            )

            rebuilt_outer = pack_op_compressed(
                rebuilt_inner,
                compressor_id=wrapper['compressor_id']
            )

            logger.info("TRANSFORMED %s", summarize_parsed_op_msg(new_parsed, "client->server"))
            return rebuilt_outer

        return raw_msg

    except Exception as e:
        logger.error("transform_message failed, forwarding raw: %s", e)
        return raw_msg