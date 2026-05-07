from dataclasses import dataclass
from enum import Enum
from typing import Optional

"""
Есть коллекция, есть в ней поля: необходимо описать, какие поля защищаются, 
какого они типа (числовые нечисловые) и какие слои для них разрешены. 

Что должен решать field_policy.py

Этот модуль должен отвечать на 4 вопроса:

Это поле вообще защищаемое или нет.
Оно числовое или нечисловое.
Какие слои у него есть: det, hope, hom.
Как называются физические поля в MongoDB, например salary__det, salary__hope, salary__hom
"""

class FieldType(str, Enum):
    STRING = "string"
    NUMBER = "number"


@dataclass(frozen=True)
class FieldPolicy:
    """
    Политика защиты одного логического поля.

    logical_name:
        Имя поля, которое видит клиент, например "name" или "salary".

    field_type:
        Тип поля: строковое или числовое.

    det_enabled:
        Разрешён ли DET-слой для операций точного равенства.

    hope_enabled:
        Разрешён ли HOPE-слой для операций сравнения и порядка.

    hom_enabled:
        Разрешён ли HOM-слой для агрегатных операций.
        Обычно имеет смысл только для числовых полей.
    """
    logical_name: str
    field_type: FieldType
    det_enabled: bool = True
    hope_enabled: bool = False
    hom_enabled: bool = False

    def det_name(self) -> str:
        return f"{self.logical_name}__det"

    def hope_name(self) -> str:
        return f"{self.logical_name}__hope"

    def hom_name(self) -> str:
        return f"{self.logical_name}__hom"


# Ключ: "database.collection.field"
FIELD_POLICIES: dict[str, FieldPolicy] = {
    # Нечисловое поле: только equality через DET
    "test_proxy.test.name": FieldPolicy(
        logical_name="name",
        field_type=FieldType.STRING,
        det_enabled=True,
        hope_enabled=False,
        hom_enabled=False,
    ),

    # Числовое поле: DET для equality, позже можно добавить HOPE и HOM
    "test_proxy.test.value": FieldPolicy(
        logical_name="value",
        field_type=FieldType.NUMBER,
        det_enabled=True,
        hope_enabled=False,
        hom_enabled=False,
    ),
}

#TODO боже что это...
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