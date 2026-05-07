import os

from dotenv import load_dotenv


load_dotenv()

#TODO пока что оч плохо и не безопасно
DET_MASTER_KEY_HEX = os.getenv("DET_MASTER_KEY_HEX")
if not DET_MASTER_KEY_HEX:
    raise RuntimeError("Environment variable DET_MASTER_KEY_HEX is not set")

DET_MASTER_KEY = bytes.fromhex(DET_MASTER_KEY_HEX)

if len(DET_MASTER_KEY) not in {16, 24, 32}:
    raise RuntimeError(
        "DET_MASTER_KEY_HEX must decode to 16, 24, or 32 bytes "
        f"(got {len(DET_MASTER_KEY)} bytes)"
    )