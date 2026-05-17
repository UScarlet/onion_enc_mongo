from decimal import Decimal
from typing import Any

from phe import paillier

from crypto_layers.crypto_hom_config import HOM_PUBLIC_KEY, HOM_PRIVATE_KEY
from transform.collection_field_info.field_policy import FieldPolicy, FieldType


def _normalize_number(value: Any) -> int | float:
    """
    Нормализовать число перед шифрованием Paillier.
    """
    if isinstance(value, bool):
        raise TypeError("Boolean is not supported as HOM number")

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        return value

    if isinstance(value, Decimal):
        return float(value)

    raise TypeError(f"Unsupported HOM number type: {type(value).__name__}")


def serialize_encrypted_number(enc: paillier.EncryptedNumber) -> dict:
    """
    Преобразовать EncryptedNumber в JSON-совместимую структуру
    для хранения в MongoDB.
    """
    return {
        "ciphertext": str(enc.ciphertext(be_secure=True)),
        "exponent": int(enc.exponent),
    }


def deserialize_encrypted_number(payload: dict) -> paillier.EncryptedNumber:
    """
    Восстановить EncryptedNumber из структуры, прочитанной из MongoDB.
    """
    return paillier.EncryptedNumber(
        public_key=HOM_PUBLIC_KEY,
        ciphertext=int(payload["ciphertext"]),
        exponent=int(payload["exponent"]),
    )


def encrypt_hom(
    value: Any,
    policy: FieldPolicy,
    db_name: str,
    collection_name: str,
) -> dict:
    """
    HOM-шифрование значения поля.

    Сейчас поддерживаются только числовые поля.
    db_name и collection_name пока не используются напрямую,
    но оставлены в интерфейсе для единообразия с DET-слоем.
    """
    if policy.field_type != FieldType.NUMBER:
        raise TypeError(f"HOM encryption is only allowed for NUMBER fields, got {policy.field_type}")

    normalized = _normalize_number(value)
    enc = HOM_PUBLIC_KEY.encrypt(normalized)
    return serialize_encrypted_number(enc)


def decrypt_hom(
    payload: dict,
    policy: FieldPolicy,
    db_name: str,
    collection_name: str,
) -> Any:
    """
    Расшифровать HOM-представление поля.
    """
    if policy.field_type != FieldType.NUMBER:
        raise TypeError(f"HOM decryption is only allowed for NUMBER fields, got {policy.field_type}")

    enc = deserialize_encrypted_number(payload)
    return HOM_PRIVATE_KEY.decrypt(enc)


def add_encrypted_payloads(items: list[dict]) -> dict:
    """
    Сложить несколько HOM-значений на стороне прокси.

    Это пригодится на следующем этапе, когда будет поддержка SUM.
    """
    if not items:
        raise ValueError("No encrypted payloads to add")

    total = deserialize_encrypted_number(items[0])

    for payload in items[1:]:
        total = total + deserialize_encrypted_number(payload)

    return serialize_encrypted_number(total)