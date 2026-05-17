import os

from dotenv import load_dotenv


load_dotenv()

#TODO пока что оч плохо и не безопасно .env
DET_MASTER_KEY_HEX = os.getenv("DET_MASTER_KEY_HEX")
if not DET_MASTER_KEY_HEX:
    raise RuntimeError("Environment variable DET_MASTER_KEY_HEX is not set")

DET_MASTER_KEY = bytes.fromhex(DET_MASTER_KEY_HEX)

if len(DET_MASTER_KEY) not in {16, 32}:
    raise RuntimeError(
        # https://datatracker.ietf.org/doc/html/rfc8452
        "DET_MASTER_KEY_HEX must decode to 16 or 32 bytes "
        f"(got {len(DET_MASTER_KEY)} bytes)"
    )