# Password Manager Telegram Bot

A secure Telegram bot for managing passwords, built with Python, aiogram, and PostgreSQL.

## Features

- **Secure Password Storage**: All passwords are encrypted using strong encryption algorithms.
- **User Authentication**: Each user has a master password that is required to access their stored passwords.
- **Password Management**: Add, view, update, and delete passwords.
- **Search Functionality**: Search for passwords by service name or username.
- **Password Generator**: Generate strong random passwords.
- **Security**: Passwords are encrypted with the user's master password and are only decrypted when needed.

## Security Features

- **Encryption**: All passwords are encrypted using Fernet symmetric encryption.
- **Secure Storage**: Master passwords are never stored in plain text; only password hashes are stored.
- **Zero Knowledge**: The bot doesn't know your actual passwords; they are only decrypted when you need them.
- **Session Management**: User sessions expire after a period of inactivity.
- **Secure Input**: Message containing passwords are deleted immediately after processing.

## Requirements

- Python 3.9 or higher
- PostgreSQL database
- Telegram Bot API token

## Environment Variables

The following environment variables need to be set:

- `BOT_TOKEN`: Your Telegram Bot API token
- `PGHOST`: PostgreSQL host
- `PGPORT`: PostgreSQL port
- `PGDATABASE`: PostgreSQL database name
- `PGUSER`: PostgreSQL username
- `PGPASSWORD`: PostgreSQL password
- `DATABASE_URL`: (Optional) PostgreSQL connection URL
- `SECRET_KEY`: A secret key for additional encryption
- `PASSWORD_SALT`: Salt for password hashing

## Usage

1. Start the bot by sending `/start`
2. Create a master password
3. Use the menu buttons to add, view, or manage your passwords

## Commands

- `/start` - Start or resume your session
- `/help` - Show help message
- `/cancel` - Cancel current operation

## Security Recommendations

1. Use a strong, unique master password
2. Never share your master password with anyone
3. The bot will never ask for external service credentials outside the normal password adding process
4. For maximum security, run the bot on your own server
