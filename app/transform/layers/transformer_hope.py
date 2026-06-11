import logging
from typing import Any
from bson import BSON
from Crypto.Util.number import inverse

from transform.collection_field_info.field_policy_access import get_field_policy
from transform.collection_field_info.field_policy import FieldType
from crypto_layers.crypto_hope import encrypt_hope, encrypt_hope_raw, _normalize_number
from crypto_layers.crypto_hope_config import HOPE_PUBLIC_KEY, HOPE_COMPARE_KEY

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

# ==========================================
# Логика для INSERT (Аугментация)
# ==========================================
def _augment_insert_document_with_hope(db_name: str, collection_name: str, doc: dict) -> dict:
    new_doc = dict(doc)
    for k, v in doc.items():
        if isinstance(v, dict):
            new_doc[k] = _augment_insert_document_with_hope(db_name, collection_name, v)
        else:
            policy = get_field_policy(db_name, collection_name, k)
            if policy and policy.hope_enabled and policy.field_type == FieldType.NUMBER:
                new_doc[policy.hope_name()] = encrypt_hope(v, policy, db_name, collection_name)
    return new_doc

# ==========================================
# Логика для FIND (Перехват $gt, $lt)
# ==========================================
def _build_hope_js_where(physical_name: str, op: str, target_value: Any) -> str:
    """Формирует JS-код с BigInt-арифметикой для выполнения HOPE на сервере."""
    n = HOPE_PUBLIC_KEY
    n_sq = n * n
    ck0, ck1 = HOPE_COMPARE_KEY
    
    m = _normalize_number(target_value)
    # Шифруем константу на прокси
    c_B = encrypt_hope_raw(m, n)
    # Сразу вычисляем обратный элемент, чтобы не нагружать сервер MongoDB
    c_B_inv = inverse(c_B, n_sq)
    
    op_map = {"$gt": ">", "$gte": ">=", "$lt": "<", "$lte": "<="}
    js_op = op_map.get(op, "==")
    
    # JavaScript функция, инжектируемая в MongoDB (BigInt)
    return f"""function() {{
        if (!this.{physical_name} || !this.{physical_name}.hope_cipher) return false;
        
        // Быстрое модульное возведение в степень для BigInt
        function modPow(base, exp, mod) {{
            let res = 1n;
            base = base % mod;
            while (exp > 0n) {{
                if (exp % 2n === 1n) res = (res * base) % mod;
                exp = exp / 2n;
                base = (base * base) % mod;
            }}
            return res;
        }}
        
        let c_A = BigInt(this.{physical_name}.hope_cipher);
        let c_B_inv = BigInt("{c_B_inv}");
        let n = BigInt("{n}");
        let n_sq = BigInt("{n_sq}");
        let ck0 = BigInt("{ck0}");
        let ck1 = BigInt("{ck1}");
        
        // 1. Гомоморфная разность
        let c_diff = (c_A * c_B_inv) % n_sq;
        
        // 2. Подавление шума ключом ck0
        let u_part = modPow(c_diff, ck0, n_sq);
        let u = (u_part - 1n) / n;
        
        // 3. Обфускация ключом ck1
        let delta_mod = (u * ck1) % n;
        
        // 4. SMOD (Симметричный модуль для отрицательных чисел)
        let half_n = n / 2n;
        let delta = delta_mod;
        if (delta > half_n) {{
            delta = delta - n;
        }}
        
        return delta {js_op} 0n;
    }}"""

def _transform_filter_with_hope(db_name: str, coll_name: str, filter_doc: dict) -> dict:
    new_filter = dict(filter_doc)
    for k, v in list(new_filter.items()):
        if k in ["$and", "$or"]:
            new_filter[k] = [_transform_filter_with_hope(db_name, coll_name, sub) for sub in v]
            continue
            
        policy = get_field_policy(db_name, coll_name, k)
        if policy and policy.hope_enabled and isinstance(v, dict):
            # Проверяем, есть ли операторы диапазона
            for op, target_value in v.items():
                if op in ["$gt", "$gte", "$lt", "$lte"]:
                    del new_filter[k]  # Удаляем открытый фильтр
                    physical_name = policy.hope_name()
                    # Заменяем на серверный JS-скрипт
                    new_filter["$where"] = _build_hope_js_where(physical_name, op, target_value)
                    break # В рамках диплома обрабатываем один диапазон за раз
                    
    return new_filter

# ==========================================
# Главная точка входа слоя HOPE
# ==========================================
def transform_client_parsed_op_msg_with_hope(parsed: dict) -> tuple[dict, bool]:
    body_idx, body_doc = _get_body_doc(parsed)
    if body_doc is None:
        return parsed, False

    db_name = body_doc.get("$db")
    command_name = _get_command_name(body_doc)

    if not db_name or command_name not in ["insert", "find"]:
        return parsed, False

    changed = False
    new_sections = []

    if command_name == "insert":
        collection_name = body_doc.get("insert")
        for sec in parsed["sections"]:
            if sec["type"] == 1 and sec.get("identifier") == "documents":
                new_docs = []
                for raw_doc in sec["documents"]:
                    original_doc = _decode_doc(raw_doc)
                    augmented_doc = _augment_insert_document_with_hope(db_name, collection_name, original_doc)
                    if augmented_doc != original_doc:
                        changed = True
                    new_docs.append(_encode_doc(augmented_doc))
                new_sections.append({"type": 1, "identifier": sec["identifier"], "documents": new_docs})
            else:
                new_sections.append(sec)

    elif command_name == "find":
        collection_name = body_doc.get("find")
        filter_doc = body_doc.get("filter", {})
        new_filter = _transform_filter_with_hope(db_name, collection_name, filter_doc)
        
        if new_filter != filter_doc:
            changed = True
            new_body = dict(body_doc)
            new_body["filter"] = new_filter
            for idx, sec in enumerate(parsed["sections"]):
                if idx == body_idx:
                    new_sections.append({"type": 0, "document": _encode_doc(new_body)})
                else:
                    new_sections.append(sec)
        else:
            new_sections = parsed["sections"]

    if not changed:
        return parsed, False

    new_parsed = {
        "header": parsed["header"],
        "flags": parsed["flags"],
        "sections": new_sections,
        "checksum": parsed.get("checksum"),
    }
    return new_parsed, True