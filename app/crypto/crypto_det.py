import base64
from decimal import Decimal
from typing import Any

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from crypto.crypto_config import DET_MASTER_KEY
from transform.collection_field_info.field_policy import FieldPolicy, FieldType


def serialize_value(value: Any, field_type: FieldType) -> bytes:
    """
    ОДНОТИПНО ОДИНАКОВО сериализовать (представить) значение поля перед DET-шифрованием.
    """
    if field_type == FieldType.STRING:
        if not isinstance(value, str):
            raise TypeError(f"Expected str for STRING field, got {type(value).__name__}")
        return value.encode("utf-8")

    if field_type == FieldType.NUMBER:
        if isinstance(value, bool):
            raise TypeError("Boolean is not supported as NUMBER field")

        if isinstance(value, int):
            return f"i:{value}".encode("utf-8")

        if isinstance(value, float):
            return f"f:{format(value, '.17g')}".encode("utf-8")

        if isinstance(value, Decimal):
            return f"d:{str(value)}".encode("utf-8")

        raise TypeError(f"Unsupported NUMBER value type: {type(value).__name__}")

    raise ValueError(f"Unsupported field type: {field_type}")


def deserialize_value(data: bytes, field_type: FieldType) -> Any:
    """
    Обратная операция к serialize_value.
    """
    if field_type == FieldType.STRING:
        return data.decode("utf-8")

    if field_type == FieldType.NUMBER:
        text = data.decode("utf-8")

        if text.startswith("i:"):
            return int(text[2:])

        if text.startswith("f:"):
            return float(text[2:])

        if text.startswith("d:"):
            return Decimal(text[2:])

        raise ValueError(f"Invalid serialized NUMBER format: {text!r}")

    raise ValueError(f"Unsupported field type: {field_type}")


def build_det_aad(db_name: str, collection_name: str, logical_field_name: str) -> bytes:
    """
    Это привязка ciphertext к контексту:

    имя базы
    имя коллекции
    логическое имя поля
    тип слоя (det)

    Благодаря этому одинаковое значение в разных полях не становится полностью взаимозаменяемым.

    #TODO пример
    """
    return f"{db_name}:{collection_name}:{logical_field_name}:det".encode("utf-8")



def encrypt_det(
    value: Any,
    policy: FieldPolicy,
    db_name: str,
    collection_name: str,
) -> str:
    """
    DET-шифрование значения поля.
    """
    plaintext = serialize_value(value, policy.field_type)
    aad = build_det_aad(db_name, collection_name, policy.logical_name)

    # Построить детерминированный nonce из aad и plaintext.
    h = hmac.HMAC(DET_MASTER_KEY, hashes.SHA256())
    h.update(aad)
    h.update(b"\x00")
    h.update(plaintext)
    nonce = h.finalize()[:12]

    cipher = AESGCMSIV(DET_MASTER_KEY)

    ciphertext = cipher.encrypt(nonce, plaintext, aad)

    blob = nonce + ciphertext
    return base64.urlsafe_b64encode(blob).decode("ascii")


def decrypt_det(
    ciphertext_b64: str,
    policy: FieldPolicy,
    db_name: str,
    collection_name: str,
) -> Any:
    """
    Обратная операция к encrypt_det.
    """
    blob = base64.urlsafe_b64decode(ciphertext_b64.encode("ascii"))

    if len(blob) < 13:
        raise ValueError("Ciphertext blob is too short")

    nonce = blob[:12]
    ciphertext = blob[12:]

    aad = build_det_aad(db_name, collection_name, policy.logical_name)
    cipher = AESGCMSIV(DET_MASTER_KEY)

    plaintext = cipher.decrypt(nonce, ciphertext, aad)
    return deserialize_value(plaintext, policy.field_type)