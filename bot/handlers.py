import os
from telethon import events, Button
from config.vars import DOWNLOAD_DIR
from bot.utils import (
    compute_sha256,
    fetch_virustotal_report,
    extract_filename,
    format_report,
)
from loguru import logger
from telethon.tl.custom import Message
from telethon.client.telegramclient import TelegramClient

session_cache = {}

def register_handlers(client: TelegramClient) -> None:
    """Register all bot event handlers."""

    @client.on(events.NewMessage(pattern="/start"))
    async def start(event: Message) -> None:
        await event.respond("👋 Привет! Отправь мне файл, и я проверю его через VirusTotal.")

    @client.on(events.NewMessage(func=lambda e: e.file))
    async def handle_document(event: Message) -> None:
        try:
            document = event.message.document
            filename = extract_filename(document)
            file_path = os.path.join(DOWNLOAD_DIR, filename)
            await event.download_media(file_path)
            logger.info(f"📥 Загружен файл: {file_path}")

            status_msg = await event.respond("🕵️ Начинаю сканирование…")

            file_hash = await compute_sha256(file_path)
            logger.info(f"🔑 SHA256: {file_hash}")

            report = await fetch_virustotal_report(file_path, file_hash)
            session_cache[event.chat_id] = {
                "report": report,
                "filename": filename,
                "document": document,
                "file_hash": file_hash,
            }

            text = format_report(report, filename, document, file_hash)
            buttons = [
                [Button.inline("🧪 Обнаружения", b"detections"), Button.inline("💉 Сигнатуры", b"signatures")],
                [Button.inline("❌ Закрыть", b"close")]
            ]
            reply = await status_msg.edit(text, buttons=buttons)
            session_cache[event.chat_id]["message"] = reply

            os.remove(file_path)
            logger.info("🧹 Временный файл удалён")

        except Exception as e:
            logger.error(f"❌ Ошибка: {e}")
            await event.respond("⚠️ Ошибка при анализе файла.")

    @client.on(events.CallbackQuery)
    async def callback_handler(event):
        chat_id = event.chat_id
        data = event.data.decode("utf-8")

        if chat_id not in session_cache:
            await event.answer("⏳ Сессия устарела. Отправь файл заново.", alert=True)
            return

        cached = session_cache[chat_id]
        report = cached["report"]
        filename = cached["filename"]
        document = cached["document"]
        file_hash = cached["file_hash"]

        if data == "detections":
            msg = "🧬 Обнаружения:\n\n"
            for engine, result in report["data"]["attributes"]["last_analysis_results"].items():
                status = "✅" if result["category"] == "undetected" else "⛔️"
                msg += f"{status} {engine}\n"
            await event.edit(msg, buttons=[[Button.inline("🔙 Назад", b"back")]])

        elif data == "signatures":
            scans = report["data"]["attributes"]["last_analysis_results"]
            found = {k: v for k, v in scans.items() if v["category"] in ["malicious", "suspicious"]}
            if not found:
                msg = "✅ Угроз не обнаружено."
            else:
                msg = "⛔️ Сигнатуры:\n\n"
                for engine, result in found.items():
                    detection = result["result"] or "Неизвестно"
                    msg += f"{engine}: {detection}\n"
            await event.edit(msg, buttons=[[Button.inline("🔙 Назад", b"back")]])

        elif data == "back":
            text = format_report(report, filename, document, file_hash)
            buttons = [
                [Button.inline("🧪 Обнаружения", b"detections"), Button.inline("💉 Сигнатуры", b"signatures")],
                [Button.inline("❌ Закрыть", b"close")]
            ]
            await event.edit(text, buttons=buttons)

        elif data == "close":
            await cached["message"].delete()
            await event.delete()
            del session_cache[chat_id]
