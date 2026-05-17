"""
Есть коллекция, есть в ней поля: необходимо описать, какие поля защищаются, 
какого они типа (числовые нечисловые) и какие слои для них разрешены. 

field_policy.py описывает эти поля в общем,
field_logic.py обрабатывает эти поля (имена зашифрованных 
и незашифрованныхполей обрабатывает), 

а здесь - в этом файлике,как раз можно описать поля какие есть
"""
from transform.collection_field_info.field_policy import FieldPolicy, FieldType

FIELD_POLICIES: dict[str, FieldPolicy] = {
    "test_proxy.test.name": FieldPolicy(
        logical_name="name",
        field_type=FieldType.STRING,
        det_enabled=True,
        hope_enabled=True,
        hom_enabled=False,
    ),
    "test_proxy.test.email": FieldPolicy(
        logical_name="email",
        field_type=FieldType.STRING,
        det_enabled=True,
        hope_enabled=True,
        hom_enabled=False,
    ),
    "test_proxy.test.salary": FieldPolicy(
        logical_name="salary",
        field_type=FieldType.NUMBER,
        det_enabled=True,
        hope_enabled=True,
        hom_enabled=True,
    ),
    "test_proxy.test.age": FieldPolicy(
        logical_name="age",
        field_type=FieldType.NUMBER,
        det_enabled=True,
        hope_enabled=True,
        hom_enabled=True,
    ),
}