import logging
from bson import BSON

# Централизованная конфигурация политик и реестр NoSQL-команд
from transform.collection_field_info.db_cmd_field_config import (
    FIELD_POLICIES,
    SUPPORTED_CLIENT_COMMANDS
)

from protocol.wire import read_int32, OP_MSG, OP_COMPRESSED
from protocol.compression import (
    parse_op_compressed_wrapper,
    unpack_op_compressed,
    pack_op_compressed,
)
from protocol.op_msg import parse_op_msg, build_op_msg
from logging_tools.inspection import summarize_parsed_op_msg

# Импорт конвейерных слоев луковичного шифрования
from transform.layers.transformer_det import (
    transform_client_parsed_op_msg_with_det,
    transform_server_parsed_op_msg_with_det,
)
from transform.layers.transformer_hom import (
    transform_client_parsed_op_msg_with_hom,
    transform_server_parsed_op_msg_with_hom,
)
from transform.layers.transformer_hope import (
    transform_client_parsed_op_msg_with_hope,
    transform_server_parsed_op_msg_with_hope,
)

logger = logging.getLogger("MongoProxy")


def _rebuild_op_msg_from_parsed(parsed: dict) -> bytes:
    """Сериализует измененный Python-словарь обратно в бинарный пакет MongoDB Wire Protocol.
    
    Когда функции encrypt_client_request или decrypt_server_response 
    закончили перекладывать и шифровать поля в Python-словаре, 
    эта функция берет измененный словарь и переводит 
    его обратно в бинарный формат пакета MongoDB 
    (со всеми сетевыми заголовками, длинами и флагами), 
    чтобы его можно было отправить через сокет в бд

    """
    return build_op_msg(
        request_id=parsed["header"][0],
        response_to=parsed["header"][1],
        flags=parsed["flags"],
        sections=parsed["sections"],
        checksum=parsed["checksum"],
    )


def _get_body_doc_for_ns(parsed: dict) -> dict | None:
    """СЕКЦИЯ 0 ПРИМЕР
        {
            "type": 0,      # payload_type
            # Внутри "document" лежат байты BSON, которые содержат:
            # {"insert": "test", "$db": "test_proxy"}
            "document": b'\x28\x00\x00\x00\x02insert\x00...' 
        }

    Это нужно чтобы узнать prefix = f"{db_name}.{coll_name}."
    """
    for sec in parsed.get("sections", []):
        if sec.get("type") == 0:
            return BSON(sec["document"]).decode()
    return None


def _cleanup_plaintext_fields(parsed: dict, db_name: str, coll_name: str) -> dict:
    """
    удаление исходных открытых полей перед записью в БД (client->server).
    Итерируется по бинарной последовательности документов секции типа 1,
    декларативно вырезая только защищаемые политикой ключи.
    """
    prefix = f"{db_name}.{coll_name}."

    # FIELD_POLICIES: dict[str, FieldPolicy] = {
    # "test_proxy.test.name": словарь1,
    # "test_proxy.test.email": словарь2,
    # "test_proxy.test.salary": словарь3 }
    # prefix = test_proxy.test.
    # тогда active_policies = [словарь1, словарь2, словарь3]
    active_policies = [p for k, p in FIELD_POLICIES.items() if k.startswith(prefix)]

    if not active_policies:
        return parsed

    for sec in parsed.get("sections", []):
        # смотрим секцию тип 1 где реальные документы, а не сам запрос
        #TODO сейчас только для инсерта надо для CRUD
        if sec.get("type") == 1 and sec.get("identifier") == "documents":
            new_docs = []
            for raw_doc in sec["documents"]:
                doc = BSON(raw_doc).decode()

                changed = False
                for policy in active_policies:
                    if policy.logical_name in doc:
                        doc.pop(policy.logical_name)
                        changed = True
                new_docs.append(BSON.encode(doc) if changed else raw_doc)
            sec["documents"] = new_docs
            
    return parsed


def _restore_logical_names(parsed: dict, db_name: str, coll_name: str) -> dict:
    """
    Супер-оптимизированное мажоритарное восстановление структуры документа (server->client).
    Выполняет इन-place верификацию параллельных слоев луковицы на предмет подмены (tampering)
    за константное время O(1) без создания Set/List объектов в куче (Zero-Allocation approach).
    """
    prefix = f"{db_name}.{coll_name}."
    active_policies = [p for k, p in FIELD_POLICIES.items() if k.startswith(prefix)]

    if not active_policies:
        return parsed

    body_idx = None
    body_doc = None
    for idx, sec in enumerate(parsed.get("sections", [])):
        if sec.get("type") == 0:
            body_idx = idx
            body_doc = BSON(sec["document"]).decode()
            break

    # Если ответ сервера не содержит курсора (например, это простой статус {"ok": 1}), прекращаем обработку
    if not body_doc or "cursor" not in body_doc:
        return parsed

    cursor = body_doc["cursor"]
    changed = False

    # Сканируем оба возможных батча курсора СУБД
    for batch_key in ["firstBatch", "nextBatch"]:
        if batch_key in cursor and isinstance(cursor[batch_key], list):
            for doc in cursor[batch_key]:
                if not isinstance(doc, dict):
                    continue
                
                # Точечно запрашиваем только физические ключи крипто-слоев по схеме
                for policy in active_policies:
                    logical_name = policy.logical_name
                    reference_value = None
                    corrupted = False
                    found_any = False

                    # 1. Извлекаем и дешифруем DET слой (базовый эталон)
                    if policy.det_enabled:
                        det_key = policy.det_name()
                        if det_key in doc:
                            reference_value = doc.pop(det_key)
                            found_any = True

                    # 2. Проверяем HOM слой на криптографическое совпадение со слоем DET
                    if policy.hom_enabled:
                        hom_key = policy.hom_name()
                        if hom_key in doc:
                            val = doc.pop(hom_key)
                            if not found_any:
                                reference_value = val
                                found_any = True
                            elif val != reference_value:
                                corrupted = True

                    # 3. Чистим технический поисковый индекс слоя HOPE
                    if policy.hope_enabled:
                        doc.pop(policy.hope_name(), None)

                    # 4. Вынесение вердикта о целостности и восстановление логического имени
                    if corrupted:
                        logger.error("CRITICAL: Data tampering detected for field '%s'! Layers mismatched.", logical_name)
                        doc[logical_name] = "ERROR_DATA_CORRUPTED"
                        changed = True
                    elif found_any:
                        doc[logical_name] = reference_value
                        changed = True

    if changed and body_idx is not None:
        parsed["sections"][body_idx]["document"] = BSON.encode(body_doc)

    return parsed


# =====================================================================
# МАРШРУТИЗАТОРЫ НАПРАВЛЕНИЙ ТРАФИКА (ДИНАМИЧЕСКИЙ NAMESPACE)
# =====================================================================

def encrypt_client_request(parsed: dict) -> tuple[dict, bool]:
    """Динамически вычисляет пространство имен и поочередно накладывает слои шифрования."""
    body_doc = _get_body_doc_for_ns(parsed)
    if not body_doc:
        return parsed, False

    db_name = body_doc.get("$db")
    if not db_name:
        return parsed, False

    # Динамический поиск целевой коллекции по зарегистрированному реестру CRUD-команд
    coll_name = None
    for cmd in SUPPORTED_CLIENT_COMMANDS.keys():
        if cmd in body_doc and isinstance(body_doc[cmd], str):
            coll_name = body_doc[cmd]
            break

    # Если это системная или конфигурационная команда (hello, ping) — мгновенный bypass
    if not coll_name:
        return parsed, False

    # Последовательный прогон пакета по конвейеру луковицы (Onion Pipeline Propagation)
    parsed, changed_det = transform_client_parsed_op_msg_with_det(parsed)
    parsed, changed_hom = transform_client_parsed_op_msg_with_hom(parsed)
    parsed, changed_hope = transform_client_parsed_op_msg_with_hope(parsed)

    # Затирание открытого текста после успешного наложения слоев
    parsed = _cleanup_plaintext_fields(parsed, db_name, coll_name)

    any_layer_changed = changed_det or changed_hom or changed_hope
    return parsed, any_layer_changed


def decrypt_server_response(parsed: dict) -> tuple[dict, bool]:
    """Динамически извлекает пространство имен из курсора ответа и запускает дешифрование."""
    body_doc = _get_body_doc_for_ns(parsed)
    if not body_doc:
        return parsed, False

    db_name = None
    coll_name = None

    # Извлечение namespace из метаданных ответа СУБД
    if "cursor" in body_doc and isinstance(body_doc["cursor"], dict) and "ns" in body_doc["cursor"]:
        ns = body_doc["cursor"]["ns"]
        if isinstance(ns, str):
            parts = ns.split(".", 1)
            if len(parts) == 2:
                db_name, coll_name = parts[0], parts[1]

    # Если в пакете нет выборки документов (простой статус {ok: 1}), дешифрование полей пропускается
    if not db_name or not coll_name:
        return parsed, False

    # Обратное последовательное дешифрование слоев
    parsed, changed_det = transform_server_parsed_op_msg_with_det(parsed)
    parsed, changed_hom = transform_server_parsed_op_msg_with_hom(parsed)
    parsed, changed_hope = transform_server_parsed_op_msg_with_hope(parsed)

    # Мажоритарная сборка логического документа СУБД
    parsed = _restore_logical_names(parsed, db_name, coll_name)

    any_layer_changed = changed_det or changed_hom or changed_hope
    return parsed, any_layer_changed


def transform_message(raw_msg: bytes, direction: str) -> bytes:
    try:
        opcode = read_int32(raw_msg, 12)

        # Обработка стандартных сообщений OP_MSG
        if opcode == OP_MSG:
            parsed = parse_op_msg(raw_msg)

            # ---------------------------------------
            if direction == "client->server":
                new_parsed, changed = encrypt_client_request(parsed)
            elif direction == "server->client":
                new_parsed, changed = decrypt_server_response(parsed)
            else:
                logger.warning("Unknown network direction: %s", direction)
                return raw_msg
            # ---------------------------------------


            if not changed:
                return raw_msg

            rebuilt = _rebuild_op_msg_from_parsed(new_parsed)
            logger.info("TRANSFORMED %s", summarize_parsed_op_msg(new_parsed, direction))
            return rebuilt

        # Обработка сжатых сообщений OP_COMPRESSED(inner=OP_MSG)
        if opcode == OP_COMPRESSED:
            wrapper = parse_op_compressed_wrapper(raw_msg)
            inner_message = unpack_op_compressed(raw_msg)
            inner_opcode = read_int32(inner_message, 12)

            if inner_opcode != OP_MSG:
                return raw_msg

            parsed = parse_op_msg(inner_message)

            # ---------------------------------------
            if direction == "client->server":
                new_parsed, changed = encrypt_client_request(parsed)
            elif direction == "server->client":
                new_parsed, changed = decrypt_server_response(parsed)
            else:
                logger.warning("Unknown network direction: %s", direction)
                return raw_msg
            # ---------------------------------------


            if not changed:
                return raw_msg

            rebuilt_inner = _rebuild_op_msg_from_parsed(new_parsed)
            rebuilt_outer = pack_op_compressed(rebuilt_inner, compressor_id=wrapper["compressor_id"])
            logger.info("TRANSFORMED %s", summarize_parsed_op_msg(new_parsed, direction))
            return rebuilt_outer

        return raw_msg

    except Exception as e:
        logger.error("transform_message critical breakdown, bypassing raw bytes: %s", e)
        return raw_msg