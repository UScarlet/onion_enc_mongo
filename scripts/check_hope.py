"""
Проверка слоя HOPE без запуска MongoDB-запросов через прокси.

Скрипт проверяет:
1. что ключи HOPE (Setup) успешно генерируются/загружаются;
2. что политики числовых полей salary и age найдены;
3. что HOPE-шифрование работает для числовых полей (Encryption);
4. что расшифровка возвращает исходные значения (Decryption);
5. что одинаковый plaintext даёт разные ciphertext (вероятностное шифрование);
6. что сравнение зашифрованных значений (Comparison) работает корректно (>, <, ==);
7. что поддерживаются отрицательные числа (благодаря smod).
"""

from pathlib import Path
import sys

# Добавляем app в sys.path для импортов
PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "app"
sys.path.insert(0, str(APP_ROOT))

from crypto_layers.crypto_hope_config import HOPE_PUBLIC_KEY, HOPE_PRIVATE_KEY, HOPE_COMPARE_KEY
from crypto_layers.crypto_hope import (
    encrypt_hope,
    decrypt_hope,
    compare_encrypted_payloads,
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
    _print_section("1. Проверка загрузки HOPE-ключей")
    print(f"Public Key (n) bits: {HOPE_PUBLIC_KEY.bit_length()}")
    print(f"Compare Key loaded: ck0 and ck1 present")
    _assert(HOPE_PUBLIC_KEY is not None and HOPE_COMPARE_KEY is not None, "Ключи HOPE успешно загружены")

    _print_section("2. Проверка политик полей")
    policy_salary = get_field_policy("test_proxy", "test", "salary")
    policy_age = get_field_policy("test_proxy", "test", "age")
    
    _assert(policy_salary is not None, "Политика для test_proxy.test.salary найдена")
    _assert(policy_age is not None, "Политика для test_proxy.test.age найдена")

    _print_section("3 & 4. Проверка шифрования и расшифровки")
    original_val = 42
    enc_payload = encrypt_hope(original_val, policy_salary, "test_proxy", "test")
    
    # Шифртексты HOPE получаются огромными, выводим только первые 30 символов
    print(f"enc({original_val}) = {enc_payload['hope_cipher'][:30]}... (truncated)")
    
    dec_val = decrypt_hope(enc_payload, policy_salary, "test_proxy", "test")
    print(f"decrypted = {dec_val}")
    _assert(dec_val == original_val, "Расшифрованное значение полностью совпадает с исходным")

    _print_section("5. Проверка вероятностного характера (рандомизации)")
    enc_payload2 = encrypt_hope(original_val, policy_salary, "test_proxy", "test")
    
    print(f"enc_1: {enc_payload['hope_cipher'][:20]}...")
    print(f"enc_2: {enc_payload2['hope_cipher'][:20]}...")
    
    _assert(
        enc_payload["hope_cipher"] != enc_payload2["hope_cipher"], 
        "Шифрование одного и того же числа дает РАЗНЫЕ шифртексты (Stateless & Randomized)"
    )

    _print_section("6. Проверка гомоморфного сравнения (серверная логика)")
    val_a = 50000
    val_b = 25000
    val_c = 50000
    
    enc_a = encrypt_hope(val_a, policy_salary, "test_proxy", "test")
    enc_b = encrypt_hope(val_b, policy_salary, "test_proxy", "test")
    enc_c = encrypt_hope(val_c, policy_salary, "test_proxy", "test")

    # Передаем зашифрованные пейлоады в функцию сравнения (имитация работы на сервере)
    cmp_a_b = compare_encrypted_payloads(enc_a, enc_b)
    cmp_b_a = compare_encrypted_payloads(enc_b, enc_a)
    cmp_a_c = compare_encrypted_payloads(enc_a, enc_c)

    print(f"compare(enc({val_a}), enc({val_b})) -> {cmp_a_b}")
    print(f"compare(enc({val_b}), enc({val_a})) -> {cmp_b_a}")
    print(f"compare(enc({val_a}), enc({val_c})) -> {cmp_a_c}")

    _assert(cmp_a_b == 1, f"Сравнение: {val_a} > {val_b} возвращает 1")
    _assert(cmp_b_a == -1, f"Сравнение: {val_b} < {val_a} возвращает -1")
    _assert(cmp_a_c == 0, f"Сравнение: {val_a} == {val_c} возвращает 0")

    _print_section("7. Проверка работы с отрицательными числами (smod)")
    val_neg = -15
    val_pos = 5
    
    enc_neg = encrypt_hope(val_neg, policy_age, "test_proxy", "test")
    enc_pos = encrypt_hope(val_pos, policy_age, "test_proxy", "test")
    
    dec_neg = decrypt_hope(enc_neg, policy_age, "test_proxy", "test")
    print(f"decrypted negative value = {dec_neg}")
    _assert(dec_neg == val_neg, f"Отрицательное число {val_neg} успешно зашифровано и расшифровано")
    
    cmp_neg_pos = compare_encrypted_payloads(enc_neg, enc_pos)
    print(f"compare(enc({val_neg}), enc({val_pos})) -> {cmp_neg_pos}")
    _assert(cmp_neg_pos == -1, f"Сравнение отрицательного и положительного ({val_neg} < {val_pos}) работает корректно")


if __name__ == '__main__':
    main()