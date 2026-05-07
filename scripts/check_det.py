"""
Проверка DET-слоя без запуска MongoDB-запросов через прокси.

Скрипт проверяет:
1. что ключ DET загружается;
2. что политики полей name и value найдены;
3. что шифрование детерминированно;
4. что расшифровка возвращает исходные значения;
5. что ciphertext зависит от контекста поля.
"""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "app"
sys.path.insert(0, str(APP_ROOT))

from crypto.crypto_config import DET_MASTER_KEY
from crypto.crypto_det import encrypt_det, decrypt_det
from transform.collection_field_info.field_policy_access import get_field_policy


def _print_section(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"[OK] {message}")


def main() -> None:
    _print_section("1. Проверка загрузки DET-ключа")
    print(f"DET key length: {len(DET_MASTER_KEY)} bytes")
    _assert(len(DET_MASTER_KEY) in {16, 24, 32}, "Ключ имеет допустимую длину")

    _print_section("2. Проверка наличия политик полей")
    policy_name = get_field_policy("test_proxy", "test", "name")
    policy_value = get_field_policy("test_proxy", "test", "value")

    _assert(policy_name is not None, "Политика для поля 'name' найдена")
    _assert(policy_value is not None, "Политика для поля 'value' найдена")

    print("policy_name  =", policy_name)
    print("policy_value =", policy_value)

    _print_section("3. Проверка DET для поля 'name'")
    c1 = encrypt_det("Alice", policy_name, "test_proxy", "test")
    c2 = encrypt_det("Alice", policy_name, "test_proxy", "test")
    c3 = encrypt_det("Bob", policy_name, "test_proxy", "test")

    print("ciphertext(name='Alice') #1 =", c1)
    print("ciphertext(name='Alice') #2 =", c2)
    print("ciphertext(name='Bob')     =", c3)

    _assert(c1 == c2, "Одинаковые значения поля 'name' дают одинаковый ciphertext")
    _assert(c1 != c3, "Разные значения поля 'name' дают разные ciphertext")

    p1 = decrypt_det(c1, policy_name, "test_proxy", "test")
    print("decrypted(name) =", p1)
    _assert(p1 == "Alice", "Расшифровка поля 'name' возвращает исходное значение")

    _print_section("4. Проверка DET для поля 'value'")
    v1 = encrypt_det(1000, policy_value, "test_proxy", "test")
    v2 = encrypt_det(1000, policy_value, "test_proxy", "test")
    v3 = encrypt_det(2000, policy_value, "test_proxy", "test")

    print("ciphertext(value=1000) #1 =", v1)
    print("ciphertext(value=1000) #2 =", v2)
    print("ciphertext(value=2000)    =", v3)

    _assert(v1 == v2, "Одинаковые значения поля 'value' дают одинаковый ciphertext")
    _assert(v1 != v3, "Разные значения поля 'value' дают разные ciphertext")

    value_plain = decrypt_det(v1, policy_value, "test_proxy", "test")
    print("decrypted(value) =", value_plain)
    _assert(value_plain == 1000, "Расшифровка поля 'value' возвращает исходное значение")

    _print_section("5. Проверка контекстной привязки")
    c_other_db = encrypt_det("Alice", policy_name, "other_db", "test")
    c_other_collection = encrypt_det("Alice", policy_name, "test_proxy", "other_collection")

    print("same value, other db         =", c_other_db)
    print("same value, other collection =", c_other_collection)

    _assert(c1 != c_other_db, "Ciphertext зависит от имени базы")
    _assert(c1 != c_other_collection, "Ciphertext зависит от имени коллекции")

    _print_section("6. Итог")
    print("Все проверки DET-слоя успешно пройдены.")


if __name__ == "__main__":
    main()