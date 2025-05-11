import logging
from aiogram import Bot, Dispatcher, types
from aiogram.contrib.fsm_storage.memory import MemoryStorage

from config import BOT_TOKEN
from database import db
from handlers import register_handlers

# Configure logging
logging.basicConfig(level=logging.INFO)

# Initialize bot and dispatcher
bot = Bot(token=BOT_TOKEN)
storage = MemoryStorage()
dp = Dispatcher(bot, storage=storage)

# Register message handlers
register_handlers(dp)

async def on_startup(dp):
    """Setup function that runs when bot starts."""
    # Create database pool
    await db.create_pool()
    logging.info("Bot started")

async def on_shutdown(dp):
    """Cleanup function that runs when bot shuts down."""
    # Close database connections
    await db.close()
    
    # Close storage
    await dp.storage.close()
    await dp.storage.wait_closed()
    
    logging.info("Bot shut down")
