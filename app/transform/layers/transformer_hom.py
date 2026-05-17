import logging
from typing import Tuple

from bson import BSON

from protocol.wire import FLAG_CHECKSUM_PRESENT
from crypto_layers.crypto_hom import encrypt_hom
from transform.collection_field_info.field_policy_access import get_field_policy
from transform.collection_field_info.field_policy import FieldType

logger = logging.getLogger("MongoProxy")


def _decode_doc(raw: bytes) -> dict:
    return BSON(raw).decode()


def _encode_doc(doc: dict) -> bytes:
    return BSON.encode(doc)


def _get_body_doc(parsed: dict) -> tuple[int | None, dict | None]:
    for idx, sec in enumerate(parsed["sections"]):
        if sec["type"] == 0:
            return idx, _decode_doc(sec["document"])
    return None, None


def _get_command_name(body_doc: dict | None) -> str | None:
    if not body_doc:
        return None

    for key in body_doc.keys():
        if key != "$db":
            return key
    return None


def _augment_insert_document_with_hom(
    db_name: str,
    collection_name: str,
    doc: dict,
) -> dict:
    """
    Добавить HOM-поля к insert-документу.

    Пример:
        {"salary": 1000, "age": 25}
    ->
        {
            "salary": 1000,
            "age": 25,
            "salary__hom": {...},
            "age__hom": {...}
        }

    Исходные логические поля пока сохраняются, потому что DET-слой
    отработает следующим этапом и заменит их на __det.
    """
    new_doc = dict(doc)

    for field_name, value in doc.items():
        policy = get_field_policy(db_name, collection_name, field_name)

        if policy is None:
            continue

        if not policy.hom_enabled:
            continue

        if policy.field_type != FieldType.NUMBER:
            continue

        hom_field_name = policy.hom_name()
        new_doc[hom_field_name] = encrypt_hom(value, policy, db_name, collection_name)

    return new_doc


def transform_client_parsed_op_msg_with_hom(parsed: dict) -> Tuple[dict, bool]:
    """
    Добавить HOM-представления в client->server OP_MSG.

    HOM-1:
    - поддерживается только insert
    - update / aggregate будут позже
    """
    if parsed["flags"] & FLAG_CHECKSUM_PRESENT:
        logger.warning("HOM rewrite skipped: OP_MSG has checksumPresent")
        return parsed, False

    body_idx, body_doc = _get_body_doc(parsed)
    if body_doc is None:
        return parsed, False

    db_name = body_doc.get("$db")
    command_name = _get_command_name(body_doc)

    if command_name != "insert" or not db_name:
        return parsed, False

    collection_name = body_doc.get("insert")
    if not collection_name:
        return parsed, False

    changed = False
    new_sections = []

    for sec in parsed["sections"]:
        if sec["type"] == 1 and sec.get("identifier") == "documents":
            new_docs = []

            for raw_doc in sec["documents"]:
                original_doc = _decode_doc(raw_doc)
                augmented_doc = _augment_insert_document_with_hom(
                    db_name,
                    collection_name,
                    original_doc,
                )

                if augmented_doc != original_doc:
                    changed = True

                new_docs.append(_encode_doc(augmented_doc))

            new_sections.append({
                "type": 1,
                "identifier": sec["identifier"],
                "documents": new_docs,
            })
        else:
            new_sections.append(sec)

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

#TODO тут похоже кода не хватает