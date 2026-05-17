"""
Проверка DET-слоя без запуска MongoDB-запросов через прокси.

Скрипт проверяет:
1. что ключ DET загружается;
2. что политики полей name, email, salary и age найдены;
3. что шифрование детерминированно;
4. что расшифровка возвращает исходные значения;
5. что ciphertext зависит от контекста поля;
6. что одинаковый plaintext в разных, но совместимых по типу полях
   даёт разные ciphertext.
"""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "app"
sys.path.insert(0, str(APP_ROOT))

from crypto_layers.crypto_det_config import DET_MASTER_KEY
from crypto_layers.crypto_det import encrypt_det, decrypt_det
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
    policy_email = get_field_policy("test_proxy", "test", "email")
    policy_salary = get_field_policy("test_proxy", "test", "salary")
    policy_age = get_field_policy("test_proxy", "test", "age")

    _assert(policy_name is not None, "Политика для поля 'name' найдена")
    _assert(policy_email is not None, "Политика для поля 'email' найдена")
    _assert(policy_salary is not None, "Политика для поля 'salary' найдена")
    _assert(policy_age is not None, "Политика для поля 'age' найдена")

    print("policy_name   =", policy_name)
    print("policy_email  =", policy_email)
    print("policy_salary =", policy_salary)
    print("policy_age    =", policy_age)

    _print_section("3. Проверка DET для строковых полей")
    name_c1 = encrypt_det("Alice", policy_name, "test_proxy", "test")
    name_c2 = encrypt_det("Alice", policy_name, "test_proxy", "test")
    name_c3 = encrypt_det("Bob", policy_name, "test_proxy", "test")

    print("ciphertext(name='Alice') #1 =", name_c1)
    print("ciphertext(name='Alice') #2 =", name_c2)
    print("ciphertext(name='Bob')      =", name_c3)

    _assert(name_c1 == name_c2, "Одинаковые значения поля 'name' дают одинаковый ciphertext")
    _assert(name_c1 != name_c3, "Разные значения поля 'name' дают разные ciphertext")
    _assert(
        decrypt_det(name_c1, policy_name, "test_proxy", "test") == "Alice",
        "Расшифровка поля 'name' возвращает исходное значение",
    )

    email_c1 = encrypt_det("alice@example.com", policy_email, "test_proxy", "test")
    email_c2 = encrypt_det("alice@example.com", policy_email, "test_proxy", "test")
    email_c3 = encrypt_det("bob@example.com", policy_email, "test_proxy", "test")

    print("ciphertext(email='alice@example.com') #1 =", email_c1)
    print("ciphertext(email='alice@example.com') #2 =", email_c2)
    print("ciphertext(email='bob@example.com')      =", email_c3)

    _assert(email_c1 == email_c2, "Одинаковые значения поля 'email' дают одинаковый ciphertext")
    _assert(email_c1 != email_c3, "Разные значения поля 'email' дают разные ciphertext")
    _assert(
        decrypt_det(email_c1, policy_email, "test_proxy", "test") == "alice@example.com",
        "Расшифровка поля 'email' возвращает исходное значение",
    )

    _print_section("4. Проверка DET для числовых полей")
    salary_c1 = encrypt_det(1000, policy_salary, "test_proxy", "test")
    salary_c2 = encrypt_det(1000, policy_salary, "test_proxy", "test")
    salary_c3 = encrypt_det(2000, policy_salary, "test_proxy", "test")

    print("ciphertext(salary=1000) #1 =", salary_c1)
    print("ciphertext(salary=1000) #2 =", salary_c2)
    print("ciphertext(salary=2000)    =", salary_c3)

    _assert(salary_c1 == salary_c2, "Одинаковые значения поля 'salary' дают одинаковый ciphertext")
    _assert(salary_c1 != salary_c3, "Разные значения поля 'salary' дают разные ciphertext")
    _assert(
        decrypt_det(salary_c1, policy_salary, "test_proxy", "test") == 1000,
        "Расшифровка поля 'salary' возвращает исходное значение",
    )

    age_c1 = encrypt_det(25, policy_age, "test_proxy", "test")
    age_c2 = encrypt_det(25, policy_age, "test_proxy", "test")
    age_c3 = encrypt_det(30, policy_age, "test_proxy", "test")

    print("ciphertext(age=25) #1 =", age_c1)
    print("ciphertext(age=25) #2 =", age_c2)
    print("ciphertext(age=30)    =", age_c3)

    _assert(age_c1 == age_c2, "Одинаковые значения поля 'age' дают одинаковый ciphertext")
    _assert(age_c1 != age_c3, "Разные значения поля 'age' дают разные ciphertext")
    _assert(
        decrypt_det(age_c1, policy_age, "test_proxy", "test") == 25,
        "Расшифровка поля 'age' возвращает исходное значение",
    )

    _print_section("5. Проверка контекстной привязки по базе и коллекции")
    name_other_db = encrypt_det("Alice", policy_name, "other_db", "test")
    name_other_collection = encrypt_det("Alice", policy_name, "test_proxy", "other_collection")

    print("same value, other db         =", name_other_db)
    print("same value, other collection =", name_other_collection)

    _assert(name_c1 != name_other_db, "Ciphertext зависит от имени базы")
    _assert(name_c1 != name_other_collection, "Ciphertext зависит от имени коллекции")

    _print_section("6. Проверка зависимости от имени поля")
    # Одинаковый plaintext в разных, но совместимых по типу полях
    same_string_name = encrypt_det("Alice", policy_name, "test_proxy", "test")
    same_string_email = encrypt_det("Alice", policy_email, "test_proxy", "test")

    same_number_salary = encrypt_det(25, policy_salary, "test_proxy", "test")
    same_number_age = encrypt_det(25, policy_age, "test_proxy", "test")

    print("same plaintext in 'name'  =", same_string_name)
    print("same plaintext in 'email' =", same_string_email)
    print("same number in 'salary'   =", same_number_salary)
    print("same number in 'age'      =", same_number_age)

    _assert(
        same_string_name != same_string_email,
        "Одинаковая строка в полях 'name' и 'email' даёт разные ciphertext",
    )
    _assert(
        same_number_salary != same_number_age,
        "Одинаковое число в полях 'salary' и 'age' даёт разные ciphertext",
    )

    print("\nПРИМЕЧАНИЕ:")
    print("Для сравнения по другому имени поля нужен совместимый тип.")
    print("У тебя 'name' и 'email' — STRING, поэтому прямое сравнение возможно.")
    print("У тебя 'salary' и 'age' — NUMBER, поэтому прямое сравнение тоже возможно.")
    print("Итог: одинаковый plaintext в разных полях даёт разные ciphertext,")
    print("потому что AAD учитывает логическое имя поля.")

    _print_section("7. Итог")
    print("Все проверки DET-слоя успешно пройдены.")


if __name__ == "__main__":
    main()