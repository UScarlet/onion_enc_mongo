"""
Проверка HOM-слоя без запуска MongoDB-запросов через прокси.

Скрипт проверяет:
1. что ключи Paillier успешно загружаются;
2. что политики числовых полей salary и age найдены;
3. что HOM-шифрование работает для числовых полей;
4. что расшифровка возвращает исходные значения;
5. что одинаковый plaintext обычно даёт разные ciphertext
   (Paillier является вероятностной, а не детерминированной криптосистемой);
6. что гомоморфное сложение ciphertext корректно работает.
"""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "app"
sys.path.insert(0, str(APP_ROOT))

from crypto_layers.crypto_hom_config import HOM_PUBLIC_KEY, HOM_PRIVATE_KEY
from crypto_layers.crypto_hom import (
    encrypt_hom,
    decrypt_hom,
    add_encrypted_payloads,
)
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
    _print_section("1. Проверка загрузки HOM-ключей")
    print("HOM public key n bits:", HOM_PUBLIC_KEY.n.bit_length())
    _assert(HOM_PUBLIC_KEY is not None, "Открытый ключ Paillier загружен")
    _assert(HOM_PRIVATE_KEY is not None, "Закрытый ключ Paillier загружен")

    _print_section("2. Проверка наличия политик числовых полей")
    policy_salary = get_field_policy("test_proxy", "test", "salary")
    policy_age = get_field_policy("test_proxy", "test", "age")

    _assert(policy_salary is not None, "Политика для поля 'salary' найдена")
    _assert(policy_age is not None, "Политика для поля 'age' найдена")
    _assert(policy_salary.hom_enabled, "Для поля 'salary' включён HOM-слой")
    _assert(policy_age.hom_enabled, "Для поля 'age' включён HOM-слой")

    print("policy_salary =", policy_salary)
    print("policy_age    =", policy_age)

    _print_section("3. Проверка HOM для поля 'salary'")
    salary_h1 = encrypt_hom(1000, policy_salary, "test_proxy", "test")
    salary_h2 = encrypt_hom(1000, policy_salary, "test_proxy", "test")
    salary_h3 = encrypt_hom(2000, policy_salary, "test_proxy", "test")

    print("ciphertext(salary=1000) #1 =", salary_h1)
    print("ciphertext(salary=1000) #2 =", salary_h2)
    print("ciphertext(salary=2000)    =", salary_h3)

    _assert(
        salary_h1 != salary_h2,
        "Одинаковые значения поля 'salary' обычно дают разные ciphertext в Paillier",
    )
    _assert(
        decrypt_hom(salary_h1, policy_salary, "test_proxy", "test") == 1000,
        "Расшифровка поля 'salary' возвращает исходное значение",
    )

    _print_section("4. Проверка HOM для поля 'age'")
    age_h1 = encrypt_hom(25, policy_age, "test_proxy", "test")
    age_h2 = encrypt_hom(25, policy_age, "test_proxy", "test")
    age_h3 = encrypt_hom(30, policy_age, "test_proxy", "test")

    print("ciphertext(age=25) #1 =", age_h1)
    print("ciphertext(age=25) #2 =", age_h2)
    print("ciphertext(age=30)    =", age_h3)

    _assert(
        age_h1 != age_h2,
        "Одинаковые значения поля 'age' обычно дают разные ciphertext в Paillier",
    )
    _assert(
        decrypt_hom(age_h1, policy_age, "test_proxy", "test") == 25,
        "Расшифровка поля 'age' возвращает исходное значение",
    )

    _print_section("5. Проверка гомоморфного сложения")
    salary_10 = encrypt_hom(10, policy_salary, "test_proxy", "test")
    salary_20 = encrypt_hom(20, policy_salary, "test_proxy", "test")
    salary_30 = encrypt_hom(30, policy_salary, "test_proxy", "test")

    encrypted_sum = add_encrypted_payloads([salary_10, salary_20, salary_30])
    decrypted_sum = decrypt_hom(encrypted_sum, policy_salary, "test_proxy", "test")

    print("enc(10) =", salary_10)
    print("enc(20) =", salary_20)
    print("enc(30) =", salary_30)
    print("hom_sum =", encrypted_sum)
    print("decrypted(hom_sum) =", decrypted_sum)

    _assert(
        decrypted_sum == 60,
        "Гомоморфное сложение ciphertext даёт корректную сумму после расшифровки",
    )

    _print_section("6. Проверка сложения для другого числового поля")
    age_5 = encrypt_hom(5, policy_age, "test_proxy", "test")
    age_7 = encrypt_hom(7, policy_age, "test_proxy", "test")

    encrypted_age_sum = add_encrypted_payloads([age_5, age_7])
    decrypted_age_sum = decrypt_hom(encrypted_age_sum, policy_age, "test_proxy", "test")

    print("enc(5) =", age_5)
    print("enc(7) =", age_7)
    print("hom_sum(age) =", encrypted_age_sum)
    print("decrypted(hom_sum(age)) =", decrypted_age_sum)

    _assert(
        decrypted_age_sum == 12,
        "Гомоморфное сложение для поля 'age' работает корректно",
    )

    print("\nПРИМЕЧАНИЕ:")
    print("В отличие от DET, HOM-слой на Paillier не является детерминированным.")
    print("Поэтому одинаковые plaintext обычно дают разные ciphertext.")
    print("Основное свойство HOM-слоя — возможность выполнять сложение")
    print("над зашифрованными значениями без предварительной расшифровки.")

    _print_section("7. Итог")
    print("Все проверки HOM-слоя успешно пройдены.")


if __name__ == "__main__":
    main()