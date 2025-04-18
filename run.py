import asyncio
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from bot.main import run_bot

if __name__ == "__main__":
    asyncio.run(run_bot())