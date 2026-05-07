from dataclasses import dataclass
from enum import Enum

"""
Базовые типы и структуры данных для описания защищаемых полей.

Этот модуль содержит:
- перечисление FieldType, задающее тип логического поля;
- dataclass FieldPolicy, описывающий политику защиты одного поля.

FieldPolicy не хранит конкретную конфигурацию базы данных, а задаёт
универсальную модель поля: его логическое имя, тип и включённые
криптографические слои (DET, HOPE, HOM).

Также объект FieldPolicy умеет формировать имена физических полей,
которые будут использоваться в MongoDB для хранения данных
на соответствующих слоях:
- <logical_name>__det
- <logical_name>__hope
- <logical_name>__hom


"""


class FieldType(str, Enum):
    STRING = "string"
    NUMBER = "number"


@dataclass(frozen=True)
class FieldPolicy:
    """
    модель поля: его логическое имя, тип и включённые
    криптографические слои (DET, HOPE, HOM)
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