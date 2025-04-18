import os
from dotenv import load_dotenv
from pathlib import Path
from loguru import logger

env_path = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")
BOT_TOKEN = os.getenv("BOT_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")

logger.info(f"ENV Loaded: API_ID={API_ID}, API_HASH={bool(API_HASH)}, BOT_TOKEN={bool(BOT_TOKEN)}, VT_API_KEY={bool(VT_API_KEY)}")

missing = []
if not API_ID: missing.append("API_ID")
if not API_HASH: missing.append("API_HASH")
if not BOT_TOKEN: missing.append("BOT_TOKEN")
if not VT_API_KEY: missing.append("VT_API_KEY")

if missing:
    logger.critical(f"🚨 Missing environment variables: {', '.join(missing)}")
    raise SystemExit("❌ Остановлено: переменные окружения не найдены.")

API_ID = int(API_ID)
DOWNLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "downloads")
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

VT_HEADERS = {
    "x-apikey": VT_API_KEY
}
