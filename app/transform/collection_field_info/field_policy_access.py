from dataclasses import dataclass
from enum import Enum
from typing import Optional

from transform.collection_field_info.field_config import FIELD_POLICIES

"""
Функции доступа к политике защищаемых полей.

Этот модуль предоставляет служебный API для работы с реестром
FIELD_POLICIES, объявленным в field_config.py.

Основные задачи модуля:
- построение канонического ключа поля;
- получение политики защиты по имени базы, коллекции и поля;
- проверка, является ли поле защищаемым;
- получение имени физического поля для нужного слоя
  (DET, HOPE, HOM);
- разбор физического имени поля обратно в пару
  (логическое имя, слой).

Таким образом, field_policy.py отделяет прикладную логику работы
с конфигурацией полей от самой конфигурации и позволяет другим
модулям проекта (например, transformer_det.py и crypto_det.py)
получать информацию о защищаемых полях через единый интерфейс.
"""

from typing import Optional

from transform.collection_field_info.field_config import FIELD_POLICIES
from transform.collection_field_info.field_policy import FieldPolicy


def make_field_key(db_name: str, collection_name: str, field_name: str) -> str:
    """
    Собрать канонический ключ поля для реестра политик.
    """
    return f"{db_name}.{collection_name}.{field_name}"


def get_field_policy(
    db_name: str,
    collection_name: str,
    field_name: str,
) -> Optional[FieldPolicy]:
    """
    Получить политику поля или None, если поле не защищается.
    """
    key = make_field_key(db_name, collection_name, field_name)
    return FIELD_POLICIES.get(key)


def is_protected_field(
    db_name: str,
    collection_name: str,
    field_name: str,
) -> bool:
    """
    Проверить, что поле входит в политику защиты.
    """
    return get_field_policy(db_name, collection_name, field_name) is not None


def get_det_field_name(
    db_name: str,
    collection_name: str,
    field_name: str,
) -> Optional[str]:
    """
    Вернуть имя физического DET-поля, если для данного логического поля
    разрешён DET-слой.
    """
    policy = get_field_policy(db_name, collection_name, field_name)
    if policy is None or not policy.det_enabled:
        return None
    return policy.det_name()


def get_hope_field_name(
    db_name: str,
    collection_name: str,
    field_name: str,
) -> Optional[str]:
    """
    Вернуть имя физического HOPE-поля, если для данного логического поля
    разрешён HOPE-слой.
    """
    policy = get_field_policy(db_name, collection_name, field_name)
    if policy is None or not policy.hope_enabled:
        return None
    return policy.hope_name()


def get_hom_field_name(
    db_name: str,
    collection_name: str,
    field_name: str,
) -> Optional[str]:
    """
    Вернуть имя физического HOM-поля, если для данного логического поля
    разрешён HOM-слой.
    """
    policy = get_field_policy(db_name, collection_name, field_name)
    if policy is None or not policy.hom_enabled:
        return None
    return policy.hom_name()


def get_physical_field_name(
    db_name: str,
    collection_name: str,
    field_name: str,
    layer: str,
) -> Optional[str]:
    """
    Вернуть физическое имя поля по имени слоя.
    """
    policy = get_field_policy(db_name, collection_name, field_name)
    if policy is None:
        return None

    if layer == "det" and policy.det_enabled:
        return policy.det_name()
    if layer == "hope" and policy.hope_enabled:
        return policy.hope_name()
    if layer == "hom" and policy.hom_enabled:
        return policy.hom_name()

    return None


def parse_physical_field_name(field_name: str) -> Optional[tuple[str, str]]:
    """
    Разобрать физическое имя поля.

    Примеры:
        "name__det"   -> ("name", "det")
        "salary__hom" -> ("salary", "hom")
    """
    if "__" not in field_name:
        return None

    logical_name, layer = field_name.rsplit("__", 1)
    if layer not in {"det", "hope", "hom"}:
        return None

    return logical_name, layer