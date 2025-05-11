import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Bot configuration
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN environment variable is not set")

# Database configuration
DB_HOST = os.getenv("PGHOST")
DB_PORT = os.getenv("PGPORT")
DB_NAME = os.getenv("PGDATABASE")
DB_USER = os.getenv("PGUSER")
DB_PASSWORD = os.getenv("PGPASSWORD")
DATABASE_URL = os.getenv("DATABASE_URL")

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")
PASSWORD_SALT = os.getenv("PASSWORD_SALT", "default_salt")

# Default master password requirements
MIN_MASTER_PASSWORD_LENGTH = 8
