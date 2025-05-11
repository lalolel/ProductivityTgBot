import logging
import asyncio
from aiogram import Dispatcher, types
from aiogram.dispatcher import FSMContext
from aiogram.dispatcher.filters.state import State, StatesGroup
from aiogram.dispatcher.filters import Text
from aiogram.types import ParseMode, CallbackQuery

from database import db
from encryption import PasswordEncryption
from keyboards import Keyboards
from utils import (
    validate_master_password, 
    validate_service_name, 
    validate_username, 
    generate_password,
    format_password_details,
    sanitize_input
)
from models import User, Password, UserSession
from config import MIN_MASTER_PASSWORD_LENGTH

# Define states for different operations
class RegistrationStates(StatesGroup):
    waiting_for_master_password = State()
    confirm_master_password = State()


class AuthenticationStates(StatesGroup):
    waiting_for_master_password = State()


class AddPasswordStates(StatesGroup):
    waiting_for_service = State()
    waiting_for_username = State()
    waiting_for_password = State()
    waiting_for_notes = State()
    confirm_add = State()


class UpdatePasswordStates(StatesGroup):
    select_field = State()
    update_service = State()
    update_username = State()
    update_password = State()
    update_notes = State()
    confirm_update = State()


class DeletePasswordStates(StatesGroup):
    confirm_delete = State()


class SearchPasswordStates(StatesGroup):
    waiting_for_search_term = State()


class ChangeMasterPasswordStates(StatesGroup):
    waiting_for_current_password = State()
    waiting_for_new_password = State()
    confirm_new_password = State()


class DeleteAccountStates(StatesGroup):
    confirm_delete = State()
    enter_master_password = State()


# Dictionary to store user sessions
user_sessions = {}


# Handler to get or create a user session
def get_user_session(user_id: int) -> UserSession:
    """Get or create user session."""
    if user_id not in user_sessions:
        user_sessions[user_id] = UserSession(user_id=user_id)
    return user_sessions[user_id]


# Basic handlers
async def cmd_start(message: types.Message):
    """Handle /start command."""
    user_id = message.from_user.id
    username = message.from_user.username
    
    # Check if user exists in the database
    user_data = await db.get_user(user_id)
    
    if user_data:
        # User exists, prompt for master password
        await message.answer(
            "Welcome back! Please enter your master password to continue.",
            reply_markup=Keyboards.cancel_keyboard()
        )
        await AuthenticationStates.waiting_for_master_password.set()
    else:
        # New user, prompt for registration
        await message.answer(
            "Welcome to the Password Manager Bot! 🔐\n\n"
            "This bot helps you securely store and retrieve your passwords.\n\n"
            "To get started, please set a strong master password. "
            "This password will be used to encrypt and decrypt your stored passwords, "
            "so make sure it's secure and that you don't forget it!\n\n"
            "Your master password should:\n"
            "• Be at least 8 characters long\n"
            "• Include uppercase and lowercase letters\n"
            "• Include at least one number\n"
            "• Include at least one special character\n\n"
            "Please enter your master password:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        await RegistrationStates.waiting_for_master_password.set()


async def cmd_help(message: types.Message):
    """Handle /help command."""
    help_text = (
        "🔐 <b>Password Manager Bot Help</b> 🔐\n\n"
        "<b>Commands:</b>\n"
        "/start - Start or resume your session\n"
        "/help - Show this help message\n"
        "/cancel - Cancel current operation\n\n"
        
        "<b>Features:</b>\n"
        "• Secure storage of your passwords\n"
        "• Add, view, update, and delete passwords\n"
        "• Search for passwords by service or username\n"
        "• Generate strong random passwords\n"
        "• Change your master password\n\n"
        
        "<b>Security:</b>\n"
        "• All passwords are encrypted with your master password\n"
        "• Your master password is never stored in plain text\n"
        "• Passwords are only decrypted when you need them\n"
        "• Session automatically expires after inactivity\n\n"
        
        "<b>Tips:</b>\n"
        "• Use a strong, unique master password\n"
        "• Don't forget your master password - it cannot be recovered!\n"
        "• Use the 'Generate' option to create strong passwords\n"
    )
    
    await message.answer(help_text, parse_mode=ParseMode.HTML)


async def cmd_cancel(message: types.Message, state: FSMContext):
    """Handle /cancel command and cancel button."""
    current_state = await state.get_state()
    
    if current_state is None:
        # No active state
        await message.answer(
            "No active operation to cancel.",
            reply_markup=Keyboards.main_menu()
        )
        return
    
    # Cancel the current state
    await state.finish()
    
    # Check if user is authenticated
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if session.is_authenticated():
        await message.answer(
            "Operation cancelled.",
            reply_markup=Keyboards.main_menu()
        )
    else:
        await message.answer(
            "Operation cancelled. Send /start to begin.",
            reply_markup=types.ReplyKeyboardRemove()
        )


# Registration handlers
async def process_master_password(message: types.Message, state: FSMContext):
    """Process master password during registration."""
    # Delete the message with the password for security
    await message.delete()
    
    master_password = message.text
    
    # Validate the password strength
    is_valid, error_message = validate_master_password(master_password, MIN_MASTER_PASSWORD_LENGTH)
    
    if not is_valid:
        await message.answer(
            f"Your password is not strong enough: {error_message}\n"
            "Please try again with a stronger password:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    # Store the password temporarily in state
    await state.update_data(master_password=master_password)
    
    # Ask for confirmation
    await message.answer(
        "Please confirm your master password by entering it again:",
        reply_markup=Keyboards.cancel_keyboard()
    )
    await RegistrationStates.confirm_master_password.set()


async def confirm_master_password(message: types.Message, state: FSMContext):
    """Confirm master password during registration."""
    # Delete the message with the password for security
    await message.delete()
    
    # Get the previously entered password
    data = await state.get_data()
    original_password = data.get('master_password')
    confirmation_password = message.text
    
    if original_password != confirmation_password:
        await message.answer(
            "Passwords don't match. Please enter your master password again:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        await RegistrationStates.waiting_for_master_password.set()
        return
    
    # Create encryption for the user
    hashed_password, salt = PasswordEncryption.setup_user_encryption(original_password)
    
    # Create the user in the database
    user_id = message.from_user.id
    username = message.from_user.username or str(user_id)
    
    success = await db.add_user(
        user_id=user_id,
        username=username,
        master_password_hash=hashed_password,
        master_salt=salt
    )
    
    if success:
        # Create user session
        session = get_user_session(user_id)
        session.authenticate(original_password)
        
        # Registration successful
        await message.answer(
            "✅ Registration successful! Your master password has been set.\n\n"
            "You can now use the password manager to securely store your passwords. "
            "Use the menu below to add, view, or manage your passwords.",
            reply_markup=Keyboards.main_menu()
        )
    else:
        # Registration failed
        await message.answer(
            "❌ Registration failed. Please try again later.",
            reply_markup=types.ReplyKeyboardRemove()
        )
    
    # Clear state
    await state.finish()


# Authentication handlers
async def process_authentication(message: types.Message, state: FSMContext):
    """Process master password during authentication."""
    # Delete the message with the password for security
    await message.delete()
    
    user_id = message.from_user.id
    master_password = message.text
    
    # Get user data from database
    user_data = await db.get_user(user_id)
    
    if not user_data:
        # User not found
        await message.answer(
            "❌ User not found. Please register first.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        await state.finish()
        return
    
    # Verify master password
    is_valid = PasswordEncryption.verify_master_password(
        master_password,
        user_data['master_password_hash'],
        user_data['master_salt']
    )
    
    if is_valid:
        # Authentication successful
        session = get_user_session(user_id)
        session.authenticate(master_password)
        
        await message.answer(
            "✅ Authentication successful!\n\n"
            "You can now use the password manager to securely store and retrieve your passwords.",
            reply_markup=Keyboards.main_menu()
        )
    else:
        # Authentication failed
        await message.answer(
            "❌ Incorrect master password. Please try again:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    # Clear state
    await state.finish()


# Password management handlers
async def cmd_add_password(message: types.Message):
    """Handle add password command."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "You need to authenticate first. Use /start to begin.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    await message.answer(
        "Please enter the service name (e.g., 'Gmail', 'Facebook', 'Twitter'):",
        reply_markup=Keyboards.cancel_keyboard()
    )
    await AddPasswordStates.waiting_for_service.set()


async def process_service_name(message: types.Message, state: FSMContext):
    """Process service name for adding a password."""
    service_name = sanitize_input(message.text)
    
    # Validate service name
    is_valid, error_message = validate_service_name(service_name)
    
    if not is_valid:
        await message.answer(
            f"Invalid service name: {error_message}\n"
            "Please try again:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    # Store service name in state
    await state.update_data(service_name=service_name)
    
    # Ask for username
    await message.answer(
        "Please enter the username or email for this service:",
        reply_markup=Keyboards.cancel_keyboard()
    )
    await AddPasswordStates.waiting_for_username.set()


async def process_username(message: types.Message, state: FSMContext):
    """Process username for adding a password."""
    username = sanitize_input(message.text)
    
    # Validate username
    is_valid, error_message = validate_username(username)
    
    if not is_valid:
        await message.answer(
            f"Invalid username: {error_message}\n"
            "Please try again:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    # Store username in state
    await state.update_data(username=username)
    
    # Create keyboard with options for password entry
    keyboard = types.ReplyKeyboardMarkup(resize_keyboard=True)
    keyboard.add(KeyboardButton("🎲 Generate Strong Password"))
    keyboard.add(KeyboardButton("❌ Cancel"))
    
    # Ask for password
    await message.answer(
        "Please enter the password for this service or use the 'Generate' button to create a strong password:",
        reply_markup=keyboard
    )
    await AddPasswordStates.waiting_for_password.set()


async def process_password(message: types.Message, state: FSMContext):
    """Process password for adding a password entry."""
    user_id = message.from_user.id
    
    # Check if user wants to generate a password
    if message.text == "🎲 Generate Strong Password":
        # Generate a strong random password
        password = generate_password()
        
        # Show the generated password to the user
        await message.answer(
            f"Generated password: <code>{password}</code>\n\n"
            "I've saved this password. Now, please enter any notes for this entry (or send 'None' if you don't have any):",
            parse_mode=ParseMode.HTML,
            reply_markup=Keyboards.cancel_keyboard()
        )
        
        # Store the generated password in state
        await state.update_data(password=password)
        await AddPasswordStates.waiting_for_notes.set()
        return
    
    # User provided their own password
    password = message.text
    
    # Delete the message with the password for security
    await message.delete()
    
    # Store the password in state
    await state.update_data(password=password)
    
    # Ask for notes
    await message.answer(
        "Please enter any notes for this entry (or send 'None' if you don't have any):",
        reply_markup=Keyboards.cancel_keyboard()
    )
    await AddPasswordStates.waiting_for_notes.set()


async def process_notes(message: types.Message, state: FSMContext):
    """Process notes for adding a password entry."""
    notes = None if message.text.lower() == 'none' else sanitize_input(message.text)
    
    # Get all stored data
    data = await state.get_data()
    service_name = data.get('service_name')
    username = data.get('username')
    password = data.get('password')
    
    # Store notes in state
    await state.update_data(notes=notes)
    
    # Display confirmation
    confirmation_text = (
        f"📝 Please confirm the details:\n\n"
        f"Service: {service_name}\n"
        f"Username: {username}\n"
        f"Password: {'*' * len(password)}\n"
    )
    
    if notes:
        confirmation_text += f"Notes: {notes}\n"
    
    confirmation_text += "\nDo you want to save this password?"
    
    await message.answer(
        confirmation_text,
        reply_markup=Keyboards.confirmation_keyboard()
    )
    await AddPasswordStates.confirm_add.set()


async def confirm_add_password(callback_query: CallbackQuery, state: FSMContext):
    """Handle confirmation for adding a password."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if callback_query.data == "confirm_yes":
        # Get all stored data
        data = await state.get_data()
        service_name = data.get('service_name')
        username = data.get('username')
        password = data.get('password')
        notes = data.get('notes')
        
        # Get user data from database
        user_data = await db.get_user(user_id)
        
        # Encrypt the password
        encrypted_password = PasswordEncryption.encrypt_password(
            password,
            session.master_password,
            user_data['master_salt']
        )
        
        if encrypted_password:
            # Add password to database
            password_id = await db.add_password(
                user_id=user_id,
                service_name=service_name,
                username=username,
                encrypted_password=encrypted_password,
                notes=notes
            )
            
            if password_id:
                await callback_query.message.answer(
                    "✅ Password has been saved successfully!",
                    reply_markup=Keyboards.main_menu()
                )
            else:
                await callback_query.message.answer(
                    "❌ Failed to save password. A password for this service and username might already exist.",
                    reply_markup=Keyboards.main_menu()
                )
        else:
            await callback_query.message.answer(
                "❌ Failed to encrypt password. Please try again later.",
                reply_markup=Keyboards.main_menu()
            )
    else:
        # User canceled
        await callback_query.message.answer(
            "Password not saved.",
            reply_markup=Keyboards.main_menu()
        )
    
    # Delete the confirmation message for security
    await callback_query.message.delete()
    
    # Clear state
    await state.finish()


async def cmd_view_passwords(message: types.Message):
    """Handle view passwords command."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "You need to authenticate first. Use /start to begin.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    # Get all passwords for the user
    passwords = await db.get_all_passwords(user_id)
    
    if not passwords:
        await message.answer(
            "You don't have any saved passwords yet. Use the 'Add Password' button to add one.",
            reply_markup=Keyboards.main_menu()
        )
        return
    
    # Create paginated keyboard with passwords
    keyboard = Keyboards.paginated_password_list(passwords)
    
    await message.answer(
        "Select a password to view:",
        reply_markup=keyboard
    )


async def cmd_search_passwords(message: types.Message):
    """Handle search passwords command."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "You need to authenticate first. Use /start to begin.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    await message.answer(
        "Please enter a search term (service name or username):",
        reply_markup=Keyboards.cancel_keyboard()
    )
    await SearchPasswordStates.waiting_for_search_term.set()


async def process_search_term(message: types.Message, state: FSMContext):
    """Process search term for passwords."""
    user_id = message.from_user.id
    search_term = sanitize_input(message.text)
    
    # Search for passwords
    passwords = await db.search_passwords(user_id, search_term)
    
    if not passwords:
        await message.answer(
            f"No passwords found matching '{search_term}'.",
            reply_markup=Keyboards.main_menu()
        )
    else:
        # Create keyboard with search results
        keyboard = Keyboards.paginated_password_list(passwords)
        
        await message.answer(
            f"Found {len(passwords)} passwords matching '{search_term}':\n"
            "Select a password to view:",
            reply_markup=keyboard
        )
    
    # Clear state
    await state.finish()


async def view_password(callback_query: CallbackQuery, state: FSMContext):
    """Handle viewing a specific password."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    # Extract password ID from callback data
    password_id = int(callback_query.data.split('_')[-1])
    
    # Get password data from database
    password_data = await db.get_password(password_id, user_id)
    
    if not password_data:
        await callback_query.message.answer(
            "Password not found or you don't have permission to view it.",
            reply_markup=Keyboards.main_menu()
        )
        return
    
    # Format the password details
    message_text = format_password_details(password_data)
    
    # Create keyboard for password actions
    keyboard = Keyboards.password_detail_keyboard(password_id)
    
    # Send the password details
    await callback_query.message.edit_text(
        message_text,
        reply_markup=keyboard,
        parse_mode=ParseMode.HTML
    )


async def show_password(callback_query: CallbackQuery):
    """Handle show password button."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "You need to authenticate first.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    # Extract password ID from callback data
    password_id = int(callback_query.data.split('_')[-1])
    
    # Get password data from database
    password_data = await db.get_password(password_id, user_id)
    
    if not password_data:
        await callback_query.message.answer(
            "Password not found or you don't have permission to view it.",
            reply_markup=Keyboards.main_menu()
        )
        return
    
    # Get user data from database
    user_data = await db.get_user(user_id)
    
    # Decrypt the password
    decrypted_password = PasswordEncryption.decrypt_password(
        password_data['encrypted_password'],
        session.master_password,
        user_data['master_salt']
    )
    
    if not decrypted_password:
        await callback_query.message.answer(
            "Failed to decrypt the password. Please try again.",
            reply_markup=Keyboards.main_menu()
        )
        return
    
    # Format the password details with the decrypted password
    message_text = format_password_details(password_data, True, decrypted_password)
    
    # Create keyboard with hide password button
    keyboard = Keyboards.hide_password_keyboard(password_id)
    
    # Update the message with the decrypted password
    await callback_query.message.edit_text(
        message_text,
        reply_markup=keyboard,
        parse_mode=ParseMode.HTML
    )
    
    # Schedule automatic hiding of password after 10 seconds
    await asyncio.sleep(30)
    
    # Check if the message still exists
    try:
        # Format the password details without the decrypted password
        message_text = format_password_details(password_data)
        
        # Create keyboard for password actions
        keyboard = Keyboards.password_detail_keyboard(password_id)
        
        # Update the message to hide the password
        await callback_query.message.edit_text(
            message_text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML
        )
    except Exception as e:
        logging.error(f"Error hiding password after timeout: {e}")


async def hide_password(callback_query: CallbackQuery):
    """Handle hide password button."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    
    # Extract password ID from callback data
    password_id = int(callback_query.data.split('_')[-1])
    
    # Get password data from database
    password_data = await db.get_password(password_id, user_id)
    
    if not password_data:
        await callback_query.message.answer(
            "Password not found or you don't have permission to view it.",
            reply_markup=Keyboards.main_menu()
        )
        return
    
    # Format the password details without the decrypted password
    message_text = format_password_details(password_data)
    
    # Create keyboard for password actions
    keyboard = Keyboards.password_detail_keyboard(password_id)
    
    # Update the message to hide the password
    await callback_query.message.edit_text(
        message_text,
        reply_markup=keyboard,
        parse_mode=ParseMode.HTML
    )


async def update_password_callback(callback_query: CallbackQuery, state: FSMContext):
    """Handle update password button."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "You need to authenticate first.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    # Extract password ID from callback data
    password_id = int(callback_query.data.split('_')[-1])
    
    # Get password data from database
    password_data = await db.get_password(password_id, user_id)
    
    if not password_data:
        await callback_query.message.answer(
            "Password not found or you don't have permission to update it.",
            reply_markup=Keyboards.main_menu()
        )
        return
    
    # Store password data in state
    await state.update_data(
        password_id=password_id,
        service_name=password_data['service_name'],
        username=password_data['username'],
        encrypted_password=password_data['encrypted_password'],
        notes=password_data['notes']
    )
    
    # Create keyboard for field selection
    keyboard = types.ReplyKeyboardMarkup(resize_keyboard=True)
    keyboard.add(KeyboardButton("Service Name"))
    keyboard.add(KeyboardButton("Username"))
    keyboard.add(KeyboardButton("Password"))
    keyboard.add(KeyboardButton("Notes"))
    keyboard.add(KeyboardButton("❌ Cancel"))
    
    await callback_query.message.answer(
        "Which field would you like to update?",
        reply_markup=keyboard
    )
    await UpdatePasswordStates.select_field.set()


async def select_update_field(message: types.Message, state: FSMContext):
    """Handle field selection for password update."""
    field = message.text
    
    if field == "Service Name":
        await message.answer(
            "Please enter the new service name:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        await UpdatePasswordStates.update_service.set()
    
    elif field == "Username":
        await message.answer(
            "Please enter the new username:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        await UpdatePasswordStates.update_username.set()
    
    elif field == "Password":
        # Create keyboard with options for password entry
        keyboard = types.ReplyKeyboardMarkup(resize_keyboard=True)
        keyboard.add(KeyboardButton("🎲 Generate Strong Password"))
        keyboard.add(KeyboardButton("❌ Cancel"))
        
        await message.answer(
            "Please enter the new password or use the 'Generate' button to create a strong password:",
            reply_markup=keyboard
        )
        await UpdatePasswordStates.update_password.set()
    
    elif field == "Notes":
        await message.answer(
            "Please enter the new notes (or send 'None' to remove notes):",
            reply_markup=Keyboards.cancel_keyboard()
        )
        await UpdatePasswordStates.update_notes.set()
    
    else:
        await message.answer(
            "Invalid field. Please select one of the options:",
            reply_markup=Keyboards.main_menu()
        )


async def update_service_name(message: types.Message, state: FSMContext):
    """Handle updating service name."""
    service_name = sanitize_input(message.text)
    
    # Validate service name
    is_valid, error_message = validate_service_name(service_name)
    
    if not is_valid:
        await message.answer(
            f"Invalid service name: {error_message}\n"
            "Please try again:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    # Update state data
    await state.update_data(service_name=service_name)
    
    # Confirm update
    data = await state.get_data()
    password_id = data.get('password_id')
    
    await message.answer(
        f"Do you want to update the service name to '{service_name}'?",
        reply_markup=Keyboards.confirmation_keyboard()
    )
    await UpdatePasswordStates.confirm_update.set()


async def update_username(message: types.Message, state: FSMContext):
    """Handle updating username."""
    username = sanitize_input(message.text)
    
    # Validate username
    is_valid, error_message = validate_username(username)
    
    if not is_valid:
        await message.answer(
            f"Invalid username: {error_message}\n"
            "Please try again:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    # Update state data
    await state.update_data(username=username)
    
    # Confirm update
    data = await state.get_data()
    password_id = data.get('password_id')
    
    await message.answer(
        f"Do you want to update the username to '{username}'?",
        reply_markup=Keyboards.confirmation_keyboard()
    )
    await UpdatePasswordStates.confirm_update.set()


async def update_password_field(message: types.Message, state: FSMContext):
    """Handle updating password field."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    # Check if user wants to generate a password
    if message.text == "🎲 Generate Strong Password":
        # Generate a strong random password
        password = generate_password()
        
        # Show the generated password to the user
        await message.answer(
            f"Generated password: <code>{password}</code>\n\n"
            "Do you want to use this password?",
            parse_mode=ParseMode.HTML,
            reply_markup=Keyboards.confirmation_keyboard()
        )
        
        # Store the generated password in state
        await state.update_data(new_password=password)
        await UpdatePasswordStates.confirm_update.set()
        return
    
    # User provided their own password
    password = message.text
    
    # Delete the message with the password for security
    await message.delete()
    
    # Update state data
    await state.update_data(new_password=password)
    
    # Confirm update
    await message.answer(
        "Do you want to update the password?",
        reply_markup=Keyboards.confirmation_keyboard()
    )
    await UpdatePasswordStates.confirm_update.set()


async def update_notes(message: types.Message, state: FSMContext):
    """Handle updating notes."""
    notes = None if message.text.lower() == 'none' else sanitize_input(message.text)
    
    # Update state data
    await state.update_data(notes=notes)
    
    # Confirm update
    note_preview = notes if notes else "No notes"
    
    await message.answer(
        f"Do you want to update the notes to '{note_preview}'?",
        reply_markup=Keyboards.confirmation_keyboard()
    )
    await UpdatePasswordStates.confirm_update.set()


async def confirm_update_password(callback_query: CallbackQuery, state: FSMContext):
    """Handle confirmation for updating a password."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if callback_query.data == "confirm_yes":
        # Get all stored data
        data = await state.get_data()
        password_id = data.get('password_id')
        service_name = data.get('service_name')
        username = data.get('username')
        new_password = data.get('new_password')
        notes = data.get('notes')
        
        encrypted_password = None
        
        # If password was updated, encrypt it
        if new_password:
            # Get user data from database
            user_data = await db.get_user(user_id)
            
            # Encrypt the new password
            encrypted_password = PasswordEncryption.encrypt_password(
                new_password,
                session.master_password,
                user_data['master_salt']
            )
            
            if not encrypted_password:
                await callback_query.message.answer(
                    "❌ Failed to encrypt password. Please try again later.",
                    reply_markup=Keyboards.main_menu()
                )
                # Delete the confirmation message for security
                await callback_query.message.delete()
                await state.finish()
                return
        
        # Update password in database
        success = await db.update_password(
            password_id=password_id,
            user_id=user_id,
            service_name=service_name,
            username=username,
            encrypted_password=encrypted_password,
            notes=notes
        )
        
        if success:
            await callback_query.message.answer(
                "✅ Password has been updated successfully!",
                reply_markup=Keyboards.main_menu()
            )
        else:
            await callback_query.message.answer(
                "❌ Failed to update password. Please try again later.",
                reply_markup=Keyboards.main_menu()
            )
    else:
        # User canceled
        await callback_query.message.answer(
            "Password update canceled.",
            reply_markup=Keyboards.main_menu()
        )
    
    # Delete the confirmation message for security
    await callback_query.message.delete()
    
    # Clear state
    await state.finish()


async def delete_password_callback(callback_query: CallbackQuery, state: FSMContext):
    """Handle delete password button."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    
    # Extract password ID from callback data
    password_id = int(callback_query.data.split('_')[-1])
    
    # Get password data from database
    password_data = await db.get_password(password_id, user_id)
    
    if not password_data:
        await callback_query.message.answer(
            "Password not found or you don't have permission to delete it.",
            reply_markup=Keyboards.main_menu()
        )
        return
    
    # Store password ID in state
    await state.update_data(password_id=password_id)
    
    # Ask for confirmation
    service_name = password_data['service_name']
    username = password_data['username']
    
    await callback_query.message.answer(
        f"Are you sure you want to delete the password for {service_name} ({username})?",
        reply_markup=Keyboards.confirmation_keyboard()
    )
    await DeletePasswordStates.confirm_delete.set()


async def confirm_delete_password(callback_query: CallbackQuery, state: FSMContext):
    """Handle confirmation for deleting a password."""
    await callback_query.answer()
    
    if callback_query.data == "confirm_yes":
        # Get password ID from state
        data = await state.get_data()
        password_id = data.get('password_id')
        user_id = callback_query.from_user.id
        
        # Delete password from database
        success = await db.delete_password(password_id, user_id)
        
        if success:
            await callback_query.message.answer(
                "✅ Password has been deleted successfully!",
                reply_markup=Keyboards.main_menu()
            )
        else:
            await callback_query.message.answer(
                "❌ Failed to delete password. Please try again later.",
                reply_markup=Keyboards.main_menu()
            )
    else:
        # User canceled
        await callback_query.message.answer(
            "Password deletion canceled.",
            reply_markup=Keyboards.main_menu()
        )
    
    # Delete the confirmation message
    await callback_query.message.delete()
    
    # Clear state
    await state.finish()


async def cmd_settings(message: types.Message):
    """Handle settings command."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "You need to authenticate first. Use /start to begin.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    await message.answer(
        "Settings menu:",
        reply_markup=Keyboards.settings_keyboard()
    )


async def cmd_change_master_password(message: types.Message):
    """Handle change master password command."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "You need to authenticate first. Use /start to begin.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    await message.answer(
        "For security, please enter your current master password:",
        reply_markup=Keyboards.cancel_keyboard()
    )
    await ChangeMasterPasswordStates.waiting_for_current_password.set()


async def verify_current_password(message: types.Message, state: FSMContext):
    """Verify current master password."""
    # Delete the message with the password for security
    await message.delete()
    
    user_id = message.from_user.id
    current_password = message.text
    
    # Get user data from database
    user_data = await db.get_user(user_id)
    
    # Verify master password
    is_valid = PasswordEncryption.verify_master_password(
        current_password,
        user_data['master_password_hash'],
        user_data['master_salt']
    )
    
    if is_valid:
        # Store current password in state
        await state.update_data(current_password=current_password)
        
        await message.answer(
            "Please enter your new master password:\n\n"
            "Your master password should:\n"
            "• Be at least 8 characters long\n"
            "• Include uppercase and lowercase letters\n"
            "• Include at least one number\n"
            "• Include at least one special character",
            reply_markup=Keyboards.cancel_keyboard()
        )
        await ChangeMasterPasswordStates.waiting_for_new_password.set()
    else:
        await message.answer(
            "❌ Incorrect master password. Please try again:",
            reply_markup=Keyboards.cancel_keyboard()
        )


async def process_new_master_password(message: types.Message, state: FSMContext):
    """Process new master password."""
    # Delete the message with the password for security
    await message.delete()
    
    new_password = message.text
    
    # Validate the password strength
    is_valid, error_message = validate_master_password(new_password, MIN_MASTER_PASSWORD_LENGTH)
    
    if not is_valid:
        await message.answer(
            f"Your password is not strong enough: {error_message}\n"
            "Please try again with a stronger password:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    # Store the new password temporarily in state
    await state.update_data(new_password=new_password)
    
    # Ask for confirmation
    await message.answer(
        "Please confirm your new master password by entering it again:",
        reply_markup=Keyboards.cancel_keyboard()
    )
    await ChangeMasterPasswordStates.confirm_new_password.set()


async def confirm_new_master_password(message: types.Message, state: FSMContext):
    """Confirm new master password."""
    # Delete the message with the password for security
    await message.delete()
    
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    # Get the previously entered password
    data = await state.get_data()
    new_password = data.get('new_password')
    current_password = data.get('current_password')
    confirmation_password = message.text
    
    if new_password != confirmation_password:
        await message.answer(
            "Passwords don't match. Please enter your new master password again:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        await ChangeMasterPasswordStates.waiting_for_new_password.set()
        return
    
    # Create new encryption for the user
    new_hashed_password, new_salt = PasswordEncryption.setup_user_encryption(new_password)
    
    # Update the master password in the database
    success = await db.update_master_password(
        user_id=user_id,
        new_password_hash=new_hashed_password,
        new_salt=new_salt
    )
    
    if success:
        # Re-encrypt all passwords with the new master password
        user_data = await db.get_user(user_id)
        passwords = await db.get_all_passwords(user_id)
        
        all_success = True
        
        for password_data in passwords:
            # Decrypt password with old master password
            decrypted_password = PasswordEncryption.decrypt_password(
                password_data['encrypted_password'],
                current_password,
                user_data['master_salt']
            )
            
            if not decrypted_password:
                all_success = False
                continue
            
            # Encrypt password with new master password
            encrypted_password = PasswordEncryption.encrypt_password(
                decrypted_password,
                new_password,
                new_salt
            )
            
            if not encrypted_password:
                all_success = False
                continue
            
            # Update password in database
            update_success = await db.update_password(
                password_id=password_data['id'],
                user_id=user_id,
                encrypted_password=encrypted_password
            )
            
            if not update_success:
                all_success = False
        
        # Update user session
        session.authenticate(new_password)
        
        if all_success:
            await message.answer(
                "✅ Master password has been changed successfully!",
                reply_markup=Keyboards.main_menu()
            )
        else:
            await message.answer(
                "⚠️ Master password has been changed, but some passwords couldn't be re-encrypted. "
                "You may need to update them manually.",
                reply_markup=Keyboards.main_menu()
            )
    else:
        await message.answer(
            "❌ Failed to change master password. Please try again later.",
            reply_markup=Keyboards.main_menu()
        )
    
    # Clear state
    await state.finish()


async def cmd_delete_account(message: types.Message):
    """Handle delete account command."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "You need to authenticate first. Use /start to begin.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    await message.answer(
        "⚠️ WARNING: This will permanently delete your account and all stored passwords!\n\n"
        "Are you sure you want to proceed?",
        reply_markup=Keyboards.confirmation_keyboard()
    )
    await DeleteAccountStates.confirm_delete.set()


async def confirm_delete_account(callback_query: CallbackQuery, state: FSMContext):
    """Handle confirmation for deleting an account."""
    await callback_query.answer()
    
    if callback_query.data == "confirm_yes":
        await callback_query.message.answer(
            "For security, please enter your master password to confirm account deletion:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        await DeleteAccountStates.enter_master_password.set()
    else:
        # User canceled
        await callback_query.message.answer(
            "Account deletion canceled.",
            reply_markup=Keyboards.main_menu()
        )
        await state.finish()
    
    # Delete the confirmation message
    await callback_query.message.delete()


async def verify_password_for_account_deletion(message: types.Message, state: FSMContext):
    """Verify master password for account deletion."""
    # Delete the message with the password for security
    await message.delete()
    
    user_id = message.from_user.id
    master_password = message.text
    
    # Get user data from database
    user_data = await db.get_user(user_id)
    
    # Verify master password
    is_valid = PasswordEncryption.verify_master_password(
        master_password,
        user_data['master_password_hash'],
        user_data['master_salt']
    )
    
    if is_valid:
        # Delete user and all passwords from database
        # This will be handled by the ON DELETE CASCADE constraint
        async with db.pool.acquire() as conn:
            await conn.execute('DELETE FROM users WHERE user_id = $1', user_id)
        
        # Clear user session
        if user_id in user_sessions:
            del user_sessions[user_id]
        
        await message.answer(
            "✅ Your account and all stored passwords have been deleted.\n\n"
            "Goodbye! Send /start if you want to create a new account.",
            reply_markup=types.ReplyKeyboardRemove()
        )
    else:
        await message.answer(
            "❌ Incorrect master password. Account deletion canceled.",
            reply_markup=Keyboards.main_menu()
        )
    
    # Clear state
    await state.finish()


async def pagination_callback(callback_query: CallbackQuery):
    """Handle pagination in password list."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    
    # Extract page number from callback data
    page = int(callback_query.data.split('_')[-1])
    
    # Get all passwords for the user
    passwords = await db.get_all_passwords(user_id)
    
    if not passwords:
        await callback_query.message.answer(
            "You don't have any saved passwords yet.",
            reply_markup=Keyboards.main_menu()
        )
        return
    
    # Create paginated keyboard with passwords
    keyboard = Keyboards.paginated_password_list(passwords, page)
    
    # Update the message with the new page
    await callback_query.message.edit_text(
        f"Select a password to view (Page {page+1}):",
        reply_markup=keyboard
    )


async def back_to_list_callback(callback_query: CallbackQuery):
    """Handle back to list button."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    
    # Get all passwords for the user
    passwords = await db.get_all_passwords(user_id)
    
    # Create paginated keyboard with passwords
    keyboard = Keyboards.paginated_password_list(passwords)
    
    # Update the message
    await callback_query.message.edit_text(
        "Select a password to view:",
        reply_markup=keyboard
    )


async def back_to_main_callback(callback_query: CallbackQuery):
    """Handle back to main button."""
    await callback_query.answer()
    
    # Delete the message
    await callback_query.message.delete()
    
    # Send main menu
    await callback_query.message.answer(
        "Main menu:",
        reply_markup=Keyboards.main_menu()
    )


def register_handlers(dp: Dispatcher):
    """Register all handlers."""
    # Basic commands
    dp.register_message_handler(cmd_start, commands=["start"])
    dp.register_message_handler(cmd_help, commands=["help"])
    dp.register_message_handler(cmd_cancel, commands=["cancel"])
    dp.register_message_handler(cmd_cancel, Text(equals="❌ Cancel", ignore_case=True), state="*")
    
    # Registration handlers
    dp.register_message_handler(
        process_master_password, 
        state=RegistrationStates.waiting_for_master_password
    )
    dp.register_message_handler(
        confirm_master_password, 
        state=RegistrationStates.confirm_master_password
    )
    
    # Authentication handlers
    dp.register_message_handler(
        process_authentication, 
        state=AuthenticationStates.waiting_for_master_password
    )
    
    # Main menu handlers
    dp.register_message_handler(cmd_add_password, Text(equals="📝 Add Password"))
    dp.register_message_handler(cmd_view_passwords, Text(equals="🔍 View Passwords"))
    dp.register_message_handler(cmd_search_passwords, Text(equals="🔎 Search"))
    dp.register_message_handler(cmd_settings, Text(equals="⚙️ Settings"))
    dp.register_message_handler(cmd_help, Text(equals="ℹ️ Help"))
    
    # Settings menu handlers
    dp.register_message_handler(cmd_change_master_password, Text(equals="🔑 Change Master Password"))
    dp.register_message_handler(cmd_delete_account, Text(equals="🗑 Delete Account"))
    dp.register_message_handler(cmd_start, Text(equals="⬅️ Back to Main Menu"))
    
    # Add password handlers
    dp.register_message_handler(
        process_service_name, 
        state=AddPasswordStates.waiting_for_service
    )
    dp.register_message_handler(
        process_username, 
        state=AddPasswordStates.waiting_for_username
    )
    dp.register_message_handler(
        process_password, 
        state=AddPasswordStates.waiting_for_password
    )
    dp.register_message_handler(
        process_notes, 
        state=AddPasswordStates.waiting_for_notes
    )
    dp.register_callback_query_handler(
        confirm_add_password, 
        lambda c: c.data.startswith("confirm_"), 
        state=AddPasswordStates.confirm_add
    )
    
    # View password handlers
    dp.register_callback_query_handler(
        view_password, 
        lambda c: c.data.startswith("view_password_")
    )
    dp.register_callback_query_handler(
        show_password, 
        lambda c: c.data.startswith("show_password_")
    )
    dp.register_callback_query_handler(
        hide_password, 
        lambda c: c.data.startswith("hide_password_")
    )
    
    # Update password handlers
    dp.register_callback_query_handler(
        update_password_callback, 
        lambda c: c.data.startswith("update_password_")
    )
    dp.register_message_handler(
        select_update_field, 
        state=UpdatePasswordStates.select_field
    )
    dp.register_message_handler(
        update_service_name, 
        state=UpdatePasswordStates.update_service
    )
    dp.register_message_handler(
        update_username, 
        state=UpdatePasswordStates.update_username
    )
    dp.register_message_handler(
        update_password_field, 
        state=UpdatePasswordStates.update_password
    )
    dp.register_message_handler(
        update_notes, 
        state=UpdatePasswordStates.update_notes
    )
    dp.register_callback_query_handler(
        confirm_update_password, 
        lambda c: c.data.startswith("confirm_"), 
        state=UpdatePasswordStates.confirm_update
    )
    
    # Delete password handlers
    dp.register_callback_query_handler(
        delete_password_callback, 
        lambda c: c.data.startswith("delete_password_")
    )
    dp.register_callback_query_handler(
        confirm_delete_password, 
        lambda c: c.data.startswith("confirm_"), 
        state=DeletePasswordStates.confirm_delete
    )
    
    # Search password handlers
    dp.register_message_handler(
        process_search_term, 
        state=SearchPasswordStates.waiting_for_search_term
    )
    
    # Change master password handlers
    dp.register_message_handler(
        verify_current_password, 
        state=ChangeMasterPasswordStates.waiting_for_current_password
    )
    dp.register_message_handler(
        process_new_master_password, 
        state=ChangeMasterPasswordStates.waiting_for_new_password
    )
    dp.register_message_handler(
        confirm_new_master_password, 
        state=ChangeMasterPasswordStates.confirm_new_password
    )
    
    # Delete account handlers
    dp.register_callback_query_handler(
        confirm_delete_account, 
        lambda c: c.data.startswith("confirm_"), 
        state=DeleteAccountStates.confirm_delete
    )
    dp.register_message_handler(
        verify_password_for_account_deletion, 
        state=DeleteAccountStates.enter_master_password
    )
    
    # Pagination handlers
    dp.register_callback_query_handler(
        pagination_callback, 
        lambda c: c.data.startswith("page_")
    )
    dp.register_callback_query_handler(
        back_to_list_callback, 
        lambda c: c.data == "back_to_list"
    )
    dp.register_callback_query_handler(
        back_to_main_callback, 
        lambda c: c.data == "back_to_main"
    )
