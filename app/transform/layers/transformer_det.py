import logging
from typing import Tuple

from bson import BSON

from protocol.wire import FLAG_CHECKSUM_PRESENT
from transform.collection_field_info.field_policy_access import (
    get_field_policy,
    get_det_field_name,
    parse_physical_field_name,
)
from crypto_layers.crypto_det import encrypt_det, decrypt_det

logger = logging.getLogger("MongoProxy")


def _decode_doc(raw: bytes) -> dict:
    return BSON(raw).decode()


def _encode_doc(doc: dict) -> bytes:
    return BSON.encode(doc)


def _get_body_doc(parsed: dict) -> tuple[int | None, dict | None]:
    """
    Найти секцию type=0 и вернуть:
        (index секции, decoded body document)
    """
    for idx, sec in enumerate(parsed["sections"]):
        if sec["type"] == 0:
            return idx, _decode_doc(sec["document"])
    return None, None


def _get_command_name(body_doc: dict | None) -> str | None:
    """
    В body_doc команда обычно хранится в первом ключе, отличном от "$db".
    Например:
        {"insert": "test", "$db": "test_proxy"}
        {"find": "test", "$db": "test_proxy"}
    """
    if not body_doc:
        return None

    for key in body_doc.keys():
        if key != "$db":
            return key
    return None


def _rewrite_insert_document_with_det(
    db_name: str,
    collection_name: str,
    doc: dict,
) -> dict:
    """
    Переписать insert-документ:
        {"name": "Alice", "salary": 1000}
    ->
        {"name__det": "...", "salary__det": "..."}
    """
    new_doc = {}

    for field_name, value in doc.items():
        policy = get_field_policy(db_name, collection_name, field_name)

        if policy is None or not policy.det_enabled:
            new_doc[field_name] = value
            continue

        det_field_name = get_det_field_name(db_name, collection_name, field_name)
        encrypted_value = encrypt_det(value, policy, db_name, collection_name)
        new_doc[det_field_name] = encrypted_value

    return new_doc


def _rewrite_find_filter_with_det(
    db_name: str,
    collection_name: str,
    filter_doc: dict,
) -> dict:
    """
    MVP-вариант rewrite для find.

    Поддерживается:
    - простой equality: {"name": "Alice"}
    - вложенные $and / $or из простых условий

    Пока не переписываются:
    - $gt / $lt / $regex
    - словари-операторы у поля
    """
    new_filter = {}

    for key, value in filter_doc.items():
        if key in {"$and", "$or"} and isinstance(value, list):
            new_filter[key] = [
                _rewrite_find_filter_with_det(db_name, collection_name, item)
                if isinstance(item, dict) else item
                for item in value
            ]
            continue

        if key.startswith("$"):
            new_filter[key] = value
            continue

        if isinstance(value, dict):
            # Для range и прочих операторов позже будет HOPE-слой
            new_filter[key] = value
            continue

        policy = get_field_policy(db_name, collection_name, key)

        if policy is None or not policy.det_enabled:
            new_filter[key] = value
            continue

        det_field_name = get_det_field_name(db_name, collection_name, key)
        encrypted_value = encrypt_det(value, policy, db_name, collection_name)
        new_filter[det_field_name] = encrypted_value

    return new_filter


def _rewrite_delete_spec_with_det(
    db_name: str,
    collection_name: str,
    delete_spec: dict,
) -> dict:
    """
    delete-спецификация имеет вид:
        {"q": {...}, "limit": 1}

    Переписываем только q.
    """
    new_spec = dict(delete_spec)

    q_doc = delete_spec.get("q")
    if isinstance(q_doc, dict):
        new_spec["q"] = _rewrite_find_filter_with_det(
            db_name,
            collection_name,
            q_doc,
        )

    return new_spec


def _decrypt_result_document(
    db_name: str,
    collection_name: str,
    doc: dict,
) -> dict:
    """
    Расшифровать DET-поля результата:
        {"name__det": "...", "salary__det": "..."}
    ->
        {"name": "Alice", "salary": 1000}

    Незащищённые поля (_id и проч.) остаются как есть.
    """
    new_doc = {}

    for field_name, value in doc.items():
        parsed = parse_physical_field_name(field_name)

        if parsed is None:
            new_doc[field_name] = value
            continue

        logical_name, layer = parsed

        if layer != "det":
            new_doc[field_name] = value
            continue

        policy = get_field_policy(db_name, collection_name, logical_name)

        if policy is None or not policy.det_enabled:
            new_doc[field_name] = value
            continue

        if not isinstance(value, str):
            new_doc[field_name] = value
            continue

        try:
            plaintext = decrypt_det(value, policy, db_name, collection_name)
            new_doc[logical_name] = plaintext
        except Exception:
            # Не ломаем весь ответ из-за одной ошибки расшифровки
            new_doc[field_name] = value

    return new_doc


def transform_client_parsed_op_msg_with_det(parsed: dict) -> Tuple[dict, bool]:
    """
    Переписать client->server OP_MSG под DET-слой.
    """
    if parsed["flags"] & FLAG_CHECKSUM_PRESENT:
        logger.warning("DET rewrite skipped: OP_MSG has checksumPresent")
        return parsed, False

    body_idx, body_doc = _get_body_doc(parsed)
    if body_doc is None:
        return parsed, False

    db_name = body_doc.get("$db")
    command_name = _get_command_name(body_doc)

    if not db_name or not command_name:
        return parsed, False

    changed = False
    new_sections = list(parsed["sections"])

    # -------------------------
    # INSERT
    # -------------------------
    if command_name == "insert":
        collection_name = body_doc.get("insert")
        if not collection_name:
            return parsed, False

        rewritten_sections = []
        for sec in parsed["sections"]:
            if sec["type"] == 1 and sec.get("identifier") == "documents":
                new_docs = []

                for raw_doc in sec["documents"]:
                    original_doc = _decode_doc(raw_doc)
                    rewritten_doc = _rewrite_insert_document_with_det(
                        db_name,
                        collection_name,
                        original_doc,
                    )

                    if rewritten_doc != original_doc:
                        changed = True

                    new_docs.append(_encode_doc(rewritten_doc))

                rewritten_sections.append({
                    "type": 1,
                    "identifier": sec["identifier"],
                    "documents": new_docs,
                })
            else:
                rewritten_sections.append(sec)

        new_sections = rewritten_sections

    # -------------------------
    # FIND
    # -------------------------
    elif command_name == "find":
        collection_name = body_doc.get("find")
        if not collection_name:
            return parsed, False

        original_filter = body_doc.get("filter")
        if isinstance(original_filter, dict):
            new_filter = _rewrite_find_filter_with_det(
                db_name,
                collection_name,
                original_filter,
            )

            if new_filter != original_filter:
                changed = True
                new_body_doc = dict(body_doc)
                new_body_doc["filter"] = new_filter

                new_sections[body_idx] = {
                    "type": 0,
                    "document": _encode_doc(new_body_doc),
                }

    # -------------------------
    # DELETE
    # -------------------------
    elif command_name == "delete":
        collection_name = body_doc.get("delete")
        if not collection_name:
            return parsed, False

        rewritten_sections = []
        for sec in parsed["sections"]:
            if sec["type"] == 1 and sec.get("identifier") == "deletes":
                new_specs = []

                for raw_doc in sec["documents"]:
                    original_spec = _decode_doc(raw_doc)
                    rewritten_spec = _rewrite_delete_spec_with_det(
                        db_name,
                        collection_name,
                        original_spec,
                    )

                    if rewritten_spec != original_spec:
                        changed = True

                    new_specs.append(_encode_doc(rewritten_spec))

                rewritten_sections.append({
                    "type": 1,
                    "identifier": sec["identifier"],
                    "documents": new_specs,
                })
            else:
                rewritten_sections.append(sec)

        new_sections = rewritten_sections

    else:
        return parsed, False

    if not changed:
        return parsed, False

    new_parsed = {
        "header": parsed["header"],
        "flags": parsed["flags"],
        "sections": new_sections,
        "checksum": parsed["checksum"],
        "raw_message": parsed["raw_message"],
    }
    return new_parsed, True


def transform_server_parsed_op_msg_with_det(parsed: dict) -> Tuple[dict, bool]:
    """
    Расшифровать server->client ответ для cursor.firstBatch / nextBatch.
    """
    if parsed["flags"] & FLAG_CHECKSUM_PRESENT:
        logger.warning("DET decrypt skipped: OP_MSG has checksumPresent")
        return parsed, False

    body_idx, body_doc = _get_body_doc(parsed)
    if body_doc is None:
        return parsed, False

    cursor = body_doc.get("cursor")
    if not isinstance(cursor, dict):
        return parsed, False

    ns = cursor.get("ns")
    if not isinstance(ns, str) or "." not in ns:
        return parsed, False

    db_name, collection_name = ns.split(".", 1)

    changed = False
    new_body_doc = dict(body_doc)
    new_cursor = dict(cursor)

    if isinstance(cursor.get("firstBatch"), list):
        old_batch = cursor["firstBatch"]
        new_batch = []

        for doc in old_batch:
            if isinstance(doc, dict):
                new_doc = _decrypt_result_document(db_name, collection_name, doc)
                if new_doc != doc:
                    changed = True
                new_batch.append(new_doc)
            else:
                new_batch.append(doc)

        new_cursor["firstBatch"] = new_batch

    if isinstance(cursor.get("nextBatch"), list):
        old_batch = cursor["nextBatch"]
        new_batch = []

        for doc in old_batch:
            if isinstance(doc, dict):
                new_doc = _decrypt_result_document(db_name, collection_name, doc)
                if new_doc != doc:
                    changed = True
                new_batch.append(new_doc)
            else:
                new_batch.append(doc)

        new_cursor["nextBatch"] = new_batch

    if not changed:
        return parsed, False

    new_body_doc["cursor"] = new_cursor
    new_sections = list(parsed["sections"])
    new_sections[body_idx] = {
        "type": 0,
        "document": _encode_doc(new_body_doc),
    }

    new_parsed = {
        "header": parsed["header"],
        "flags": parsed["flags"],
        "sections": new_sections,
        "checksum": parsed["checksum"],
        "raw_message": parsed["raw_message"],
    }
    return new_parsed, True