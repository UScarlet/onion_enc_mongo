# ЭТО ФАЙЛ ПОДРОБНОГО ЛОГИРОВАНИЯ

import logging
from pprint import pformat
from bson import BSON

from wire import read_int32, OP_MSG, OP_COMPRESSED
from compression import unpack_op_compressed
from op_msg import parse_op_msg, get_command_name

logger = logging.getLogger("MongoProxy")


# ============================================================
# Вспомогательные функции
# ============================================================

def _get_body_doc(parsed: dict) -> dict | None:
    """
    Вернуть body-документ из секции type 0, если он есть.

    Для многих MongoDB-команд основная информация о команде
    лежит именно в секции type 0.
    """
    for sec in parsed["sections"]:
        if sec["type"] == 0:
            return BSON(sec["document"]).decode()
    return None


def _get_sequence_docs(parsed: dict, identifier: str) -> list[dict]:
    """
    Вернуть все документы из секций type 1 с заданным identifier.

    Используется для команд, у которых полезные данные находятся
    не в body type 0, а в document sequence type 1, например delete, update
    """
    result = []
    for sec in parsed["sections"]:
        if sec["type"] == 1 and sec.get("identifier") == identifier:
            for raw_doc in sec["documents"]:
                result.append(BSON(raw_doc).decode())
    return result



def _block(title: str, value, indent: str = "    ") -> str:
    """
    Сформировать многострочный блок вида:

    title:
        ...
    """
    formatted = pformat(value, width=100, sort_dicts=False)
    indented = "\n".join(indent + line for line in formatted.splitlines())
    return f"{title}:\n{indented}"


# ============================================================
# Обработчики client -> server
# ============================================================

def summarize_hello(parsed: dict, body_doc: dict, direction: str) -> str:
    request_id = parsed["header"][0]
    db_name = body_doc.get("$db")

    parts = [
        f"{direction}",
        f"  request_id: {request_id}",
        f"  command: hello",
        f"  db: {db_name}",
        _block("  body", body_doc),
    ]
    return "\n".join(parts)


def summarize_find(parsed: dict, body_doc: dict, direction: str) -> str:
    request_id = parsed["header"][0]
    db_name = body_doc.get("$db")

    parts = [
        f"{direction}",
        f"  request_id: {request_id}",
        f"  command: find",
        f"  db: {db_name}",
        f"  collection: {body_doc.get('find')}",
        _block("  filter", body_doc.get("filter")),
        _block("  body", body_doc),
    ]
    return "\n".join(parts)


def summarize_insert(parsed: dict, body_doc: dict, direction: str) -> str:
    request_id = parsed["header"][0]
    db_name = body_doc.get("$db")
    docs = _get_sequence_docs(parsed, "documents")

    parts = [
        f"{direction}",
        f"  request_id: {request_id}",
        f"  command: insert",
        f"  db: {db_name}",
        f"  collection: {body_doc.get('insert')}",
        f"  documents_count: {len(docs)}",
        _block("  documents", docs),
        _block("  body", body_doc),
    ]
    return "\n".join(parts)


def summarize_delete(parsed: dict, body_doc: dict, direction: str) -> str:
    request_id = parsed["header"][0]
    db_name = body_doc.get("$db")
    deletes = _get_sequence_docs(parsed, "deletes")

    parts = [
        f"{direction}",
        f"  request_id: {request_id}",
        f"  command: delete",
        f"  db: {db_name}",
        f"  collection: {body_doc.get('delete')}",
        f"  deletes_count: {len(deletes)}",
        _block("  deletes", deletes),
        _block("  body", body_doc),
    ]
    return "\n".join(parts)


def summarize_update(parsed: dict, body_doc: dict, direction: str) -> str:
    request_id = parsed["header"][0]
    db_name = body_doc.get("$db")
    updates = _get_sequence_docs(parsed, "updates")

    parts = [
        f"{direction}",
        f"  request_id: {request_id}",
        f"  command: update",
        f"  db: {db_name}",
        f"  collection: {body_doc.get('update')}",
        f"  updates_count: {len(updates)}",
        _block("  updates", updates),
        _block("  body", body_doc),
    ]
    return "\n".join(parts)


def summarize_default_client(parsed: dict, body_doc: dict, direction: str) -> str:
    """
    Обработчик по умолчанию для client->server,
    если для команды нет специального summarizer.
    """
    request_id = parsed["header"][0]
    db_name = body_doc.get("$db")
    command_name = get_command_name(body_doc)

    parts = [
        f"{direction}",
        f"  request_id: {request_id}",
        f"  command: {command_name}",
        f"  db: {db_name}",
        _block("  body", body_doc),
    ]
    return "\n".join(parts)


# ============================================================
# Обработчики server -> client
# ============================================================

def summarize_cursor_reply(parsed: dict, body_doc: dict, direction: str) -> str:
    response_to = parsed["header"][1]
    cursor = body_doc.get("cursor", {})
    batch = cursor.get("firstBatch") or cursor.get("nextBatch") or []

    parts = [
        f"{direction}",
        f"  response_to: {response_to}",
        f"  command: cursor",
        f"  ok: {body_doc.get('ok')}",
        f"  batch_count: {len(batch)}",
        _block("  batch", batch),
        _block("  body", body_doc),
    ]
    return "\n".join(parts)


def summarize_write_reply(parsed: dict, body_doc: dict, direction: str) -> str:
    response_to = parsed["header"][1]

    parts = [
        f"{direction}",
        f"  response_to: {response_to}",
        f"  command: write-reply",
        f"  ok: {body_doc.get('ok')}",
        f"  n: {body_doc.get('n')}",
        _block("  body", body_doc),
    ]
    return "\n".join(parts)


def summarize_default_server(parsed: dict, body_doc: dict, direction: str) -> str:
    """
    Обработчик по умолчанию для server->client,
    если ответ не распознан как cursor/write-reply.
    """
    response_to = parsed["header"][1]

    parts = [
        f"{direction}",
        f"  response_to: {response_to}",
        f"  command: {get_command_name(body_doc)}",
        f"  ok: {body_doc.get('ok') if body_doc else None}",
        _block("  body", body_doc),
    ]
    return "\n".join(parts)


# ============================================================
# Таблицы обработчиков
# ============================================================

CLIENT_COMMAND_SUMMARIZERS = {
    "hello": summarize_hello,
    "find": summarize_find,
    "insert": summarize_insert,
    "delete": summarize_delete,
    "update": summarize_update,
}


def _select_server_reply_summarizer(body_doc: dict):
    """
    Выбрать summarizer для ответа сервера по содержимому body_doc.
    """
    if "cursor" in body_doc:
        return summarize_cursor_reply

    if "n" in body_doc and "ok" in body_doc:
        return summarize_write_reply

    return summarize_default_server


# ============================================================
# Главная функция построения лога
# ============================================================

def summarize_parsed_op_msg(parsed: dict, direction: str) -> str:
    """
    Построить подробное многострочное представление already-parsed OP_MSG.

    Архитектура:
    - сначала определяется body_doc;
    - затем определяется команда;
    - затем выбирается соответствующий обработчик из таблицы;
    - если обработчик не найден, используется fallback по умолчанию.

    Чтобы добавить новую команду, достаточно написать новую функцию
    summarize_<command>() и добавить её в CLIENT_COMMAND_SUMMARIZERS.
    """
    body_doc = _get_body_doc(parsed)

    if direction == "client->server":
        if not body_doc:
            request_id = parsed["header"][0]
            return "\n".join([
                f"{direction}",
                f"  request_id: {request_id}",
                f"  body: <none>",
            ])

        command_name = get_command_name(body_doc)
        handler = CLIENT_COMMAND_SUMMARIZERS.get(command_name, summarize_default_client)
        return handler(parsed, body_doc, direction)

    if not body_doc:
        response_to = parsed["header"][1]
        return "\n".join([
            f"{direction}",
            f"  response_to: {response_to}",
            f"  body: <none>",
        ])

    handler = _select_server_reply_summarizer(body_doc)
    return handler(parsed, body_doc, direction)

