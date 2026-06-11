import json
import os
from pathlib import Path
import random
from Crypto.Util.number import getPrime, GCD, inverse
from dotenv import load_dotenv

load_dotenv()

HOPE_KEY_BITS = int(os.getenv("HOPE_KEY_BITS", "2048"))
HOPE_KEYS_DIR = Path(os.getenv("HOPE_KEYS_DIR", "keys"))
HOPE_KEYS_PATH = HOPE_KEYS_DIR / "hope_keys.json"

def generate_hope_keys(bits: int = 2048) -> dict:
    """Алгоритм 1: Setup Algorithm for HOPE"""
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # Генерация ключа сравнения ck
    while True:
        zeta = random.randrange(1, n)
        if GCD(zeta, n) == 1:
            break
            
    # n^{1/3} ограничение для eta (берем треть битовой длины)
    bound_bits = bits // 3
    while True:
        eta0 = random.getrandbits(bound_bits)
        if eta0 > 0 and GCD(eta0, n) == 1:
            break
            
    while True:
        eta1 = random.getrandbits(bound_bits)
        if eta1 > 0 and GCD(eta1, n) == 1:
            break
            
   
    # А вот обратный элемент для ck1 всё так же вычисляется в кольце Z_n
    phi_zeta_mod_n = (phi_n * zeta) % n
    phi_zeta_inv = inverse(phi_zeta_mod_n, n)
    
    # ИСПРАВЛЕНИЕ: ck0 должен быть огромным целым числом, кратным phi_n.
    # Никакого взятия по модулю n для ck0 здесь быть не должно!
    ck0 = eta0 * phi_n * zeta
    ck1 = (eta1 * phi_zeta_inv) % n
    
    return {
        "pk": n,               # Открытый ключ (модуль)
        "sk": phi_n,           # Закрытый ключ 
        "ck0": ck0,            # Часть 0 ключа сравнения
        "ck1": ck1             # Часть 1 ключа сравнения
    }

def _ensure_keys() -> dict:
    HOPE_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    if not HOPE_KEYS_PATH.exists():
        keys = generate_hope_keys(HOPE_KEY_BITS)
        HOPE_KEYS_PATH.write_text(json.dumps(keys, indent=2), encoding="utf-8")
        return keys
    
    return json.loads(HOPE_KEYS_PATH.read_text(encoding="utf-8"))

_keys = _ensure_keys()
HOPE_PUBLIC_KEY = _keys["pk"]
HOPE_PRIVATE_KEY = _keys["sk"]
HOPE_COMPARE_KEY = (_keys["ck0"], _keys["ck1"])