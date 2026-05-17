import random
from typing import Any
from Crypto.Util.number import GCD, inverse

from transform.collection_field_info.field_policy import FieldPolicy, FieldType
from crypto_layers.crypto_hope_config import HOPE_PUBLIC_KEY, HOPE_PRIVATE_KEY, HOPE_COMPARE_KEY

def smod(x: int, n: int) -> int:
    """Симметричный модуль (smod) для поддержки отрицательных чисел."""
    half_n = n // 2
    return (x + half_n) % n - half_n

def _normalize_number(value: Any) -> int:
    """Приведение значения к целому числу (HOPE работает с целыми)."""
    if isinstance(value, bool):
        raise TypeError("Boolean is not supported as HOPE number")
    if isinstance(value, (int, float)):
        return int(value)
    raise TypeError(f"Unsupported HOPE number type: {type(value).__name__}")

def encrypt_hope_raw(m: int, pk: int) -> int:
    """Алгоритм 2: Encryption Algorithm for HOPE"""
    n = pk
    n_sq = n * n
    half_n = n // 2
    
    # Проверка принадлежности открытого текста допустимому диапазону
    if not (-half_n <= m < half_n):
        raise ValueError("Plaintext out of bounds for HOPE encryption")
        
    m_mod_n = m % n
    
    # Выбор случайного числа r
    while True:
        r = random.randrange(1, n)
        if GCD(r, n) == 1:
            break
            
    # c ≡ (n+1)^m * r^n mod n^2
    c = (pow(n + 1, m_mod_n, n_sq) * pow(r, n, n_sq)) % n_sq
    return c

def decrypt_hope_raw(c: int, pk: int, sk: int) -> int:
    """Алгоритм 4: Decryption Algorithm for HOPE"""
    n = pk
    n_sq = n * n
    phi_n = sk
    
    # m ≡ ((c^phi_n mod n^2 - 1) / n) * phi_n^(-1) mod n
    u = (pow(c, phi_n, n_sq) - 1) // n
    phi_n_inv = inverse(phi_n, n)
    
    m_mod_n = (u * phi_n_inv) % n
    
    # Корректировка через симметричный модуль (smod)
    return smod(m_mod_n, n)

def compare_hope_raw(c0: int, c1: int, pk: int, ck: tuple[int, int]) -> int:
    """Алгоритм 3: Comparison Algorithm for HOPE (выполняется на сервере)"""
    n = pk
    n_sq = n * n
    ck0, ck1 = ck
    
    # Шаг 1: Гомоморфное вычитание c0 ⊖ c1 = c0 * c1^(-1) mod n^2
    c1_inv = inverse(c1, n_sq)
    c_diff = (c0 * c1_inv) % n_sq
    
    # Шаг 2: Вычисление рандомизированной разницы ∆
    u = (pow(c_diff, ck0, n_sq) - 1) // n
    delta_mod_n = (u * ck1) % n
    delta = smod(delta_mod_n, n)
    
    # Шаг 3: Возврат знака ∆
    if delta > 0:
        return 1
    elif delta == 0:
        return 0
    else:
        return -1

# ==========================================================
# Обертки для использования в трансформере
# ==========================================================

def serialize_encrypted_hope(c: int) -> dict:
    return {"hope_cipher": str(c)}

def deserialize_encrypted_hope(payload: dict) -> int:
    return int(payload["hope_cipher"])

def encrypt_hope(value: Any, policy: FieldPolicy, db_name: str, collection_name: str) -> dict:
    if policy.field_type != FieldType.NUMBER:
        raise TypeError(f"HOPE encryption is only allowed for NUMBER fields")
    m = _normalize_number(value)
    enc = encrypt_hope_raw(m, HOPE_PUBLIC_KEY)
    return serialize_encrypted_hope(enc)

def decrypt_hope(payload: dict, policy: FieldPolicy, db_name: str, collection_name: str) -> Any:
    if policy.field_type != FieldType.NUMBER:
        raise TypeError(f"HOPE decryption is only allowed for NUMBER fields")
    c = deserialize_encrypted_hope(payload)
    return decrypt_hope_raw(c, HOPE_PUBLIC_KEY, HOPE_PRIVATE_KEY)

def compare_encrypted_payloads(payload1: dict, payload2: dict) -> int:
    """
    Возвращает:
      1, если payload1 > payload2
      0, если payload1 == payload2
     -1, если payload1 < payload2
    """
    c0 = deserialize_encrypted_hope(payload1)
    c1 = deserialize_encrypted_hope(payload2)
    return compare_hope_raw(c0, c1, HOPE_PUBLIC_KEY, HOPE_COMPARE_KEY)