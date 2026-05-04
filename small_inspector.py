from op_msg import get_command_name
from big_inspector import (
    _get_body_doc,
    _get_sequence_docs,
    )


# ============================================================
# Вспомогательное
# ============================================================

def _short(value, max_len: int = 180) -> str:
    """
    Короткое строковое представление значения для лога.
    """
    text = repr(value)
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


# ============================================================
# Краткие обработчики client -> server
# ============================================================




def summarize_find(parsed: dict, body_doc: dict, direction: str) -> str:
    request_id = parsed["header"][0]
    db_name = body_doc.get("$db")

    parts = [
        f"{direction}",
        f"  req: {request_id}",
        f"  cmd: find",
        f"  db: {db_name}",
        f"  coll: {body_doc.get('find')}",
        f"  filter: {_short(body_doc.get('filter'))}",
        f"  limit: {body_doc.get('limit')}",
        f"  singleBatch: {body_doc.get('singleBatch')}",
    ]
    return "\n".join(parts)


def summarize_insert(parsed: dict, body_doc: dict, direction: str) -> str:
    request_id = parsed["header"][0]
    db_name = body_doc.get("$db")
    coll = body_doc.get("insert")
    docs = _get_sequence_docs(parsed, "documents")
    first_doc = docs[0] if docs else None

    parts = [
        f"{direction}",
        f"  req: {request_id}",
        f"  cmd: insert",
        f"  db: {db_name}",
        f"  coll: {coll}",
        f"  docs_count: {len(docs)}",
        f"  first_doc: {_short(first_doc)}",
    ]
    return "\n".join(parts)


def summarize_delete(parsed: dict, body_doc: dict, direction: str) -> str:
    request_id = parsed["header"][0]
    db_name = body_doc.get("$db")
    coll = body_doc.get("delete")
    deletes = _get_sequence_docs(parsed, "deletes")
    first_q = deletes[0].get("q") if deletes else None

    parts = [
        f"{direction}",
        f"  req: {request_id}",
        f"  cmd: delete",
        f"  db: {db_name}",
        f"  coll: {coll}",
        f"  deletes_count: {len(deletes)}",
        f"  first_q: {_short(first_q)}",
    ]
    return "\n".join(parts)


def summarize_update(parsed: dict, body_doc: dict, direction: str) -> str:
    request_id = parsed["header"][0]
    db_name = body_doc.get("$db")
    coll = body_doc.get("update")
    updates = _get_sequence_docs(parsed, "updates")
    first_update = updates[0] if updates else None

    parts = [
        f"{direction}",
        f"  req: {request_id}",
        f"  cmd: update",
        f"  db: {db_name}",
        f"  coll: {coll}",
        f"  updates_count: {len(updates)}",
        f"  first_update: {_short(first_update)}",
    ]
    return "\n".join(parts)


def summarize_default_client(parsed: dict, body_doc: dict, direction: str) -> str:
    command_name = get_command_name(body_doc)
    return  f"  cmd: {command_name}"


# ============================================================
# Краткие обработчики server -> client не нужны
# ============================================================


def summarize_cursor_reply(parsed: dict, body_doc: dict, direction: str) -> str:
    response_to = parsed["header"][1]
    cursor = body_doc.get("cursor", {})
    batch = cursor.get("firstBatch") or cursor.get("nextBatch") or []
    first_doc = batch[0] if batch else None

    parts = [
        f"{direction}",
        f"  resp_to: {response_to}",
        f"  cmd: cursor",
        f"  ok: {body_doc.get('ok')}",
        f"  batch_count: {len(batch)}",
        f"  first_doc: {_short(first_doc)}",
    ]
    return "\n".join(parts)


def summarize_write_reply(parsed: dict, body_doc: dict, direction: str) -> str:
    response_to = parsed["header"][1]

    parts = [
        f"{direction}",
        f"  resp_to: {response_to}",
        f"  cmd: write-reply",
        f"  ok: {body_doc.get('ok')}",
        f"  n: {body_doc.get('n')}",
    ]
    return "\n".join(parts)


def summarize_default_server(parsed: dict, body_doc: dict, direction: str) -> str:
    
    return f"  cmd: {get_command_name(body_doc)}"


# ============================================================
# Таблицы обработчиков
# ============================================================

CLIENT_COMMAND_SUMMARIZERS = {
    "find": summarize_find,
    "insert": summarize_insert,
    "delete": summarize_delete,
    "update": summarize_update,
}


def _select_server_reply_summarizer(body_doc: dict):

    if "cursor" in body_doc:
        return summarize_cursor_reply

    if "n" in body_doc and "ok" in body_doc:
        return summarize_write_reply

    return summarize_default_server


# ============================================================
# Главная функция построения мини-лога
# ============================================================

def summarize_parsed_op_msg(parsed: dict, direction: str) -> str:
    # короткий лог
    body_doc = _get_body_doc(parsed)

    if direction == "client->server":
        if not body_doc:
            request_id = parsed["header"][0]
            return "\n".join([
                f"{direction}",
                f"  req: {request_id}",
                f"  body: <none>",
            ])

        command_name = get_command_name(body_doc)
        handler = CLIENT_COMMAND_SUMMARIZERS.get(command_name, summarize_default_client)
        return handler(parsed, body_doc, direction)

    if not body_doc:
        response_to = parsed["header"][1]
        return "\n".join([
            f"{direction}",
            f"  resp_to: {response_to}",
            f"  body: <none>",
        ])

    handler = _select_server_reply_summarizer(body_doc)
    return handler(parsed, body_doc, direction)


