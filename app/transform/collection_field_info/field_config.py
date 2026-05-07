from transform.collection_field_info.field_policy import FieldPolicy, FieldType
"""
Есть коллекция, есть в ней поля: необходимо описать, какие поля защищаются, 
какого они типа (числовые нечисловые) и какие слои для них разрешены. 

field_policy.py описывает эти поля в общем,
field_logic. pyобрабатывает эти поля (имена зашифрованных 
и незашифрованныхполей обрабатывает), 

а здесь - в этом файлике,как раз можно описать поля какие есть
"""

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