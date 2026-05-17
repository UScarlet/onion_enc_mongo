import json
import os
from pathlib import Path

from dotenv import load_dotenv
from phe import paillier


load_dotenv()

HOM_KEY_BITS = int(os.getenv("HOM_KEY_BITS", "2048"))
HOM_KEYS_DIR = Path(os.getenv("HOM_KEYS_DIR", "keys"))

PUBLIC_KEY_PATH = HOM_KEYS_DIR / "paillier_public.json"
PRIVATE_KEY_PATH = HOM_KEYS_DIR / "paillier_private.json"


def _save_keys(public_key: paillier.PaillierPublicKey, private_key: paillier.PaillierPrivateKey) -> None:
    HOM_KEYS_DIR.mkdir(parents=True, exist_ok=True)

    public_payload = {
        "n": str(public_key.n),
    }

    private_payload = {
        "p": str(private_key.p),
        "q": str(private_key.q),
    }

    PUBLIC_KEY_PATH.write_text(json.dumps(public_payload, indent=2), encoding="utf-8")
    PRIVATE_KEY_PATH.write_text(json.dumps(private_payload, indent=2), encoding="utf-8")


def _load_public_key() -> paillier.PaillierPublicKey:
    payload = json.loads(PUBLIC_KEY_PATH.read_text(encoding="utf-8"))
    return paillier.PaillierPublicKey(n=int(payload["n"]))


def _load_private_key(public_key: paillier.PaillierPublicKey) -> paillier.PaillierPrivateKey:
    payload = json.loads(PRIVATE_KEY_PATH.read_text(encoding="utf-8"))
    return paillier.PaillierPrivateKey(
        public_key=public_key,
        p=int(payload["p"]),
        q=int(payload["q"]),
    )


def _ensure_keys() -> tuple[paillier.PaillierPublicKey, paillier.PaillierPrivateKey]:
    if PUBLIC_KEY_PATH.exists() and PRIVATE_KEY_PATH.exists():
        public_key = _load_public_key()
        private_key = _load_private_key(public_key)
        return public_key, private_key

    public_key, private_key = paillier.generate_paillier_keypair(n_length=HOM_KEY_BITS)
    _save_keys(public_key, private_key)
    return public_key, private_key


HOM_PUBLIC_KEY, HOM_PRIVATE_KEY = _ensure_keys()