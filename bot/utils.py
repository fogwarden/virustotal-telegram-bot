import aiohttp
import hashlib
import time
from config.vars import VT_HEADERS
from typing import Any, Dict, Optional


def safe(val: Optional[Any], default: Any) -> Any:
    return val if val is not None else default


async def compute_sha256(file_path: str) -> str:
    """Compute SHA256 hash of a file asynchronously."""
    loop = __import__("asyncio").get_event_loop()
    return await loop.run_in_executor(None, lambda: _hash_file(file_path))


def _hash_file(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()


def extract_filename(document: Any) -> str:
    """Extract filename from Telethon document."""
    from telethon.tl.types import DocumentAttributeFilename
    for attr in document.attributes:
        if isinstance(attr, DocumentAttributeFilename):
            return attr.file_name
    return "unnamed"


async def fetch_virustotal_report(file_path: str, file_hash: str) -> Dict:
    """Try to fetch VT report, otherwise upload and wait for analysis."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=VT_HEADERS) as resp:
            if resp.status == 200:
                return await resp.json()

        with open(file_path, "rb") as f:
            form = aiohttp.FormData()
            form.add_field("file", f, filename=file_path)
            async with session.post("https://www.virustotal.com/api/v3/files", headers=VT_HEADERS, data=form) as upload:
                if upload.status in [200, 201]:
                    data = await upload.json()
                    analysis_id = data["data"]["id"]
                    return await _wait_for_analysis(session, analysis_id)
    raise RuntimeError("Не удалось получить отчёт или загрузить файл")


async def _wait_for_analysis(session: aiohttp.ClientSession, analysis_id: str) -> Dict:
    """Poll VT API until analysis is done (max ~90 sec)."""
    for _ in range(30):
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        async with session.get(url, headers=VT_HEADERS) as resp:
            if resp.status == 200:
                result = await resp.json()
                if result["data"]["attributes"]["status"] == "completed":
                    file_id = result["meta"]["file_info"]["sha256"]
                    async with session.get(f"https://www.virustotal.com/api/v3/files/{file_id}", headers=VT_HEADERS) as final:
                        return await final.json()
        await __import__("asyncio").sleep(3)
    raise TimeoutError("Анализ VT не завершён за отведённое время")


def human_size(size: int) -> str:
    """Format size in bytes to human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024.0:
            return f"{size:.2f}{unit}"
        size /= 1024.0
    return f"{size:.2f}TB"


def format_report(data: Dict, filename: str, document: Any, file_hash: str) -> str:
    """Format a detailed VirusTotal scan report as Telegram message."""
    attrs = data["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    detected = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(stats.values())
    first_ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(attrs.get("first_submission_date", 0)))
    last_ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(attrs.get("last_analysis_date", 0)))
    magic = attrs.get("magic", "Неизвестно")
    mime = safe(getattr(document, "mime_type", None), "неизвестно")
    size = safe(getattr(document, "size", None), 0)

    return f"""
🧬 Обнаружения: {detected} / {total}

🔖 Имя файла: {filename}
🔒 Формат файла: {mime}
📁 Размер файла: {human_size(size)}

🔬 Первый анализ: {first_ts}
🔭 Последний анализ: {last_ts}

🎉 Magic: {magic}

⚜️ [VirusTotal](https://www.virustotal.com/gui/file/{file_hash}/detection)
"""
