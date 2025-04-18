from telethon import TelegramClient
from config.vars import API_ID, API_HASH, BOT_TOKEN
from bot.handlers import register_handlers
from loguru import logger


async def run_bot() -> None:
    logger.info("Initialize and run the Telegram bot...")
    client = TelegramClient("bot", API_ID, API_HASH)
    await client.start(bot_token=BOT_TOKEN)

    register_handlers(client)
    logger.info("Bot started")
    await client.run_until_disconnected()
