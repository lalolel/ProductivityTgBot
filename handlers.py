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
    calculate_password_strength,
    format_password_details,
    sanitize_input,
    import_passwords_from_json,
    export_passwords_to_json
)
from models import User, Password, UserSession, Category, SecureNote, CustomField
from config import MIN_MASTER_PASSWORD_LENGTH

# Define states for different operations
class RegistrationStates(StatesGroup):
    waiting_for_master_password = State()
    confirm_master_password = State()
    
class AuthenticationStates(StatesGroup):
    waiting_for_master_password = State()
    
class PasswordStates(StatesGroup):
    waiting_for_service = State()
    waiting_for_username = State()
    waiting_for_password = State()
    waiting_for_notes = State()
    confirm_add = State()
    confirm_delete = State()
    confirm_update = State()
    
class CategoryStates(StatesGroup):
    waiting_for_name = State()
    confirm_delete = State()
    add_category = State()
    edit_category = State()
    delete_category = State()
    set_password_category = State()
    set_note_category = State()
    
class SecureNoteStates(StatesGroup):
    waiting_for_title = State()
    waiting_for_content = State()
    confirm_add = State()
    update_title = State()
    update_content = State()
    confirm_update = State()
    confirm_delete = State()
    
class PasswordGeneratorStates(StatesGroup):
    set_length = State()
    
class ImportExportStates(StatesGroup):
    waiting_for_import_file = State()
    confirm_import = State()
    select_export_format = State()
    select_export_type = State()

# Global dictionary to store password generator options for each user
password_gen_options = {}


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
    
    
class CategoryStates(StatesGroup):
    add_category = State()
    edit_category = State()
    delete_category = State()
    set_password_category = State()
    set_note_category = State()


class SecureNoteStates(StatesGroup):
    waiting_for_title = State()
    waiting_for_content = State()
    confirm_add = State()
    update_title = State()
    update_content = State()
    confirm_update = State()
    confirm_delete = State()


# Duplicate classes removed
    
    
class PasswordShareStates(StatesGroup):
    select_user = State()
    confirm_share = State()
    set_expiration = State()


# Category related handlers
async def cmd_categories(message: types.Message):
    """Handle categories command."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "You need to authenticate first. Use /start to begin.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    # Get categories for the user
    categories = await db.get_categories(user_id)
    
    await message.answer(
        "📁 <b>Categories</b>\n\n"
        "Organize your passwords and secure notes in categories for easy access.\n"
        "Select a category to view its contents:",
        reply_markup=Keyboards.categories_keyboard(categories),
        parse_mode=ParseMode.HTML
    )


async def process_category_action(callback_query: CallbackQuery):
    """Handle category selection."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    data = callback_query.data
    
    if data == "category_all":
        # Show all passwords
        passwords = await db.get_all_passwords(user_id)
        
        if not passwords:
            await callback_query.message.edit_text(
                "You don't have any passwords yet. Add some passwords first.",
                reply_markup=Keyboards.back_to_main_inline()
            )
            return
        
        # Prepare message
        message_text = "🔍 <b>All Passwords</b>\n\n"
        
        # Display paginated passwords
        page = 0
        page_size = 5
        total_pages = (len(passwords) + page_size - 1) // page_size
        
        # Create keyboard with pagination
        keyboard = Keyboards.paginated_password_list(passwords, page)
        
        await callback_query.message.edit_text(
            message_text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML
        )
        
    elif data == "category_none":
        # Show uncategorized passwords
        passwords = await db.get_passwords_by_category(user_id, None)
        
        if not passwords:
            await callback_query.message.edit_text(
                "You don't have any uncategorized passwords.",
                reply_markup=Keyboards.back_to_categories_inline()
            )
            return
        
        # Prepare message
        message_text = "📂 <b>Uncategorized Passwords</b>\n\n"
        
        # Display paginated passwords
        page = 0
        keyboard = Keyboards.paginated_password_list(passwords, page)
        
        await callback_query.message.edit_text(
            message_text,
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML
        )
        
    elif data.startswith("category_"):
        # Extract category id
        category_id = int(data.split("_")[1])
        
        # Get category info
        category = await db.get_category(category_id, user_id)
        
        if not category:
            await callback_query.message.edit_text(
                "Category not found.",
                reply_markup=Keyboards.back_to_categories_inline()
            )
            return
        
        # Get passwords in this category
        passwords = await db.get_passwords_by_category(user_id, category_id)
        
        # Get secure notes in this category
        notes = await db.get_secure_notes_by_category(user_id, category_id)
        
        if not passwords and not notes:
            await callback_query.message.edit_text(
                f"Category '{category['name']}' is empty. Add some passwords or notes to this category.",
                reply_markup=Keyboards.back_to_categories_inline()
            )
            return
        
        # Prepare message
        message_text = f"📂 <b>Category: {category['name']}</b>\n\n"
        
        if passwords:
            message_text += "<b>Passwords:</b>\n"
            # Display paginated passwords
            page = 0
            keyboard = Keyboards.paginated_password_list(passwords, page, include_category_back=True)
        else:
            message_text += "<b>No passwords in this category</b>\n"
            
        if notes:
            if not passwords:
                message_text += "\n"
            message_text += "<b>Secure Notes:</b>\n"
            # For now, just show the number of notes
            message_text += f"{len(notes)} secure notes found.\n"
            
        await callback_query.message.edit_text(
            message_text,
            reply_markup=keyboard if passwords else Keyboards.back_to_categories_inline(),
            parse_mode=ParseMode.HTML
        )


async def manage_categories(callback_query: CallbackQuery):
    """Handle manage categories button."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    # Get categories for the user
    categories = await db.get_categories(user_id)
    
    await callback_query.message.edit_text(
        "📁 <b>Manage Categories</b>\n\n"
        "Add, edit, or delete categories.",
        reply_markup=Keyboards.manage_categories_keyboard(categories),
        parse_mode=ParseMode.HTML
    )


async def add_category(callback_query: CallbackQuery):
    """Handle add category button."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    await CategoryStates.add_category.set()
    
    await callback_query.message.edit_text(
        "📝 <b>Add New Category</b>\n\n"
        "Please enter a name for the new category:",
        reply_markup=Keyboards.cancel_inline(),
        parse_mode=ParseMode.HTML
    )


async def process_category_name(message: types.Message, state: FSMContext):
    """Process new category name."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        await state.finish()
        return
    
    # Sanitize and validate the input
    category_name = sanitize_input(message.text.strip())
    
    if not category_name:
        await message.answer(
            "❌ Category name cannot be empty. Please try again:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    if len(category_name) > 50:
        await message.answer(
            "❌ Category name is too long (max 50 characters). Please try again:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    # Add the category
    category_id = await db.add_category(user_id, category_name)
    
    if category_id:
        # Log the action
        await db.add_audit_log(
            user_id, 
            "create", 
            "category", 
            category_id, 
            {"name": category_name}
        )
        
        await message.answer(
            f"✅ Category '{category_name}' added successfully.",
            reply_markup=Keyboards.main_menu()
        )
    else:
        await message.answer(
            "❌ Failed to add category. Please try again later.",
            reply_markup=Keyboards.main_menu()
        )
    
    # Clear state
    await state.finish()


async def edit_category(callback_query: CallbackQuery, state: FSMContext):
    """Handle edit category button."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    # Extract category id
    category_id = int(callback_query.data.split("_")[-1])
    
    # Get category info
    category = await db.get_category(category_id, user_id)
    
    if not category:
        await callback_query.message.edit_text(
            "Category not found.",
            reply_markup=Keyboards.back_to_categories_inline()
        )
        return
    
    # Store category id in state
    await state.update_data(category_id=category_id, current_name=category['name'])
    await CategoryStates.edit_category.set()
    
    await callback_query.message.edit_text(
        f"✏️ <b>Edit Category</b>\n\n"
        f"Current name: <b>{category['name']}</b>\n\n"
        f"Please enter a new name for the category:",
        reply_markup=Keyboards.cancel_inline(),
        parse_mode=ParseMode.HTML
    )


async def process_edit_category_name(message: types.Message, state: FSMContext):
    """Process edited category name."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        await state.finish()
        return
    
    # Get state data
    data = await state.get_data()
    category_id = data.get("category_id")
    current_name = data.get("current_name")
    
    # Sanitize and validate the input
    new_name = sanitize_input(message.text.strip())
    
    if not new_name:
        await message.answer(
            "❌ Category name cannot be empty. Please try again:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    if len(new_name) > 50:
        await message.answer(
            "❌ Category name is too long (max 50 characters). Please try again:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    if new_name == current_name:
        await message.answer(
            "❌ New name is the same as the current name. No changes made.",
            reply_markup=Keyboards.main_menu()
        )
        await state.finish()
        return
    
    # Update the category
    success = await db.update_category(category_id, user_id, new_name)
    
    if success:
        # Log the action
        await db.add_audit_log(
            user_id, 
            "update", 
            "category", 
            category_id, 
            {"old_name": current_name, "new_name": new_name}
        )
        
        await message.answer(
            f"✅ Category renamed from '{current_name}' to '{new_name}'.",
            reply_markup=Keyboards.main_menu()
        )
    else:
        await message.answer(
            "❌ Failed to update category. Please try again later.",
            reply_markup=Keyboards.main_menu()
        )
    
    # Clear state
    await state.finish()


async def delete_category(callback_query: CallbackQuery, state: FSMContext):
    """Handle delete category button."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    # Extract category id
    category_id = int(callback_query.data.split("_")[-1])
    
    # Get category info
    category = await db.get_category(category_id, user_id)
    
    if not category:
        await callback_query.message.edit_text(
            "Category not found.",
            reply_markup=Keyboards.back_to_categories_inline()
        )
        return
    
    # Get passwords in this category
    passwords = await db.get_passwords_by_category(user_id, category_id)
    
    # Get secure notes in this category
    notes = await db.get_secure_notes_by_category(user_id, category_id)
    
    # Store category id in state
    await state.update_data(
        category_id=category_id, 
        category_name=category['name'],
        password_count=len(passwords),
        note_count=len(notes)
    )
    await CategoryStates.delete_category.set()
    
    warning_text = ""
    if passwords or notes:
        warning_text = (
            f"⚠️ <b>Warning:</b> This category contains {len(passwords)} password(s) "
            f"and {len(notes)} note(s). Deleting this category will move all items to 'Uncategorized'.\n\n"
        )
    
    await callback_query.message.edit_text(
        f"🗑️ <b>Delete Category</b>\n\n"
        f"Are you sure you want to delete the category '{category['name']}'?\n\n"
        f"{warning_text}"
        f"This action cannot be undone.",
        reply_markup=Keyboards.confirm_delete_category_keyboard(category_id),
        parse_mode=ParseMode.HTML
    )


async def process_delete_category(callback_query: CallbackQuery, state: FSMContext):
    """Process category deletion confirmation."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        await state.finish()
        return
    
    data = await state.get_data()
    category_id = data.get("category_id")
    category_name = data.get("category_name")
    
    if callback_query.data == f"confirm_delete_category_yes_{category_id}":
        # Delete the category
        success = await db.delete_category(category_id, user_id)
        
        if success:
            # Log the action
            await db.add_audit_log(
                user_id, 
                "delete", 
                "category", 
                category_id, 
                {"name": category_name}
            )
            
            await callback_query.message.edit_text(
                f"✅ Category '{category_name}' deleted successfully.",
                reply_markup=Keyboards.back_to_categories_inline()
            )
        else:
            await callback_query.message.edit_text(
                "❌ Failed to delete category. Please try again later.",
                reply_markup=Keyboards.back_to_categories_inline()
            )
    else:
        # User canceled the deletion
        await callback_query.message.edit_text(
            f"❌ Category deletion canceled.",
            reply_markup=Keyboards.back_to_categories_inline()
        )
    
    # Clear state
    await state.finish()


async def back_to_categories(callback_query: CallbackQuery):
    """Handle back to categories button."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    # Get categories for the user
    categories = await db.get_categories(user_id)
    
    await callback_query.message.edit_text(
        "📁 <b>Categories</b>\n\n"
        "Organize your passwords and secure notes in categories for easy access.\n"
        "Select a category to view its contents:",
        reply_markup=Keyboards.categories_keyboard(categories),
        parse_mode=ParseMode.HTML
    )


# Tools related handlers
async def cmd_tools(message: types.Message):
    """Handle tools command."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "You need to authenticate first. Use /start to begin.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    await message.answer(
        "⚒️ <b>Tools</b>\n\n"
        "Select a tool:",
        reply_markup=Keyboards.tools_keyboard(),
        parse_mode=ParseMode.HTML
    )
    
    
# Secure note handlers
async def cmd_add_note(message: types.Message):
    """Handle add note command."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "You need to authenticate first. Use /start to begin.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    await SecureNoteStates.waiting_for_title.set()
    
    await message.answer(
        "📋 <b>Add Secure Note</b>\n\n"
        "Please enter a title for your note:",
        reply_markup=Keyboards.cancel_keyboard(),
        parse_mode=ParseMode.HTML
    )


async def process_note_title(message: types.Message, state: FSMContext):
    """Process secure note title."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        await state.finish()
        return
    
    # Sanitize and validate the input
    title = sanitize_input(message.text.strip())
    
    if not title:
        await message.answer(
            "❌ Title cannot be empty. Please try again:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    if len(title) > 100:
        await message.answer(
            "❌ Title is too long (max 100 characters). Please try again:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    # Store title in state
    await state.update_data(title=title)
    await SecureNoteStates.waiting_for_content.set()
    
    await message.answer(
        f"✅ Title: <b>{title}</b>\n\n"
        f"Now please enter the content of your note:",
        reply_markup=Keyboards.cancel_keyboard(),
        parse_mode=ParseMode.HTML
    )


async def process_note_content(message: types.Message, state: FSMContext):
    """Process secure note content."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        await state.finish()
        return
    
    # Sanitize the input
    content = sanitize_input(message.text)
    
    if not content:
        await message.answer(
            "❌ Content cannot be empty. Please try again:",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    # Store content in state
    await state.update_data(content=content)
    
    # Get data from state
    data = await state.get_data()
    title = data.get("title")
    
    # Encrypt the content
    master_password = session.master_password
    encrypted_content = PasswordEncryption.encrypt_password(content, master_password)
    
    # Store encrypted content in state
    await state.update_data(encrypted_content=encrypted_content)
    await SecureNoteStates.confirm_add.set()
    
    # Show preview and confirmation
    await message.answer(
        f"📋 <b>Secure Note Preview</b>\n\n"
        f"<b>Title:</b> {title}\n"
        f"<b>Content:</b> {content}\n\n"
        f"Save this note?",
        reply_markup=Keyboards.confirmation_keyboard(),
        parse_mode=ParseMode.HTML
    )


async def confirm_add_note(callback_query: CallbackQuery, state: FSMContext):
    """Handle confirmation of adding a note."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        await state.finish()
        return
    
    if callback_query.data == "confirm_yes":
        # Get data from state
        data = await state.get_data()
        title = data.get("title")
        encrypted_content = data.get("encrypted_content")
        
        # Add note to database
        note_id = await db.add_secure_note(user_id, title, encrypted_content)
        
        if note_id:
            # Log the action
            await db.add_audit_log(
                user_id, 
                "create", 
                "secure_note", 
                note_id, 
                {"title": title}
            )
            
            await callback_query.message.edit_text(
                f"✅ Secure note '{title}' added successfully.",
                reply_markup=Keyboards.back_to_main_inline()
            )
        else:
            await callback_query.message.edit_text(
                "❌ Failed to add secure note. Please try again later.",
                reply_markup=Keyboards.back_to_main_inline()
            )
    else:
        # User canceled the operation
        await callback_query.message.edit_text(
            "❌ Operation canceled.",
            reply_markup=Keyboards.back_to_main_inline()
        )
    
    # Clear state
    await state.finish()


async def cmd_view_notes(message: types.Message):
    """Handle view notes command."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "You need to authenticate first. Use /start to begin.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    # Get all secure notes for this user
    notes = await db.get_all_secure_notes(user_id)
    
    if not notes:
        await message.answer(
            "You don't have any secure notes yet. Use the 'Add Note' option to create one.",
            reply_markup=Keyboards.main_menu()
        )
        return
    
    # Create paginated list of notes
    page = 0
    keyboard = Keyboards.paginated_note_list(notes, page)
    
    await message.answer(
        "📑 <b>Your Secure Notes</b>\n\n"
        "Select a note to view:",
        reply_markup=keyboard,
        parse_mode=ParseMode.HTML
    )


async def view_note(callback_query: CallbackQuery):
    """Handle viewing a secure note."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    # Extract note id
    note_id = int(callback_query.data.split("_")[-1])
    
    # Get note from database
    note = await db.get_secure_note(note_id, user_id)
    
    if not note:
        await callback_query.message.edit_text(
            "Note not found.",
            reply_markup=Keyboards.back_to_main_inline()
        )
        return
    
    # Decrypt the content
    master_password = session.master_password
    decrypted_content = PasswordEncryption.decrypt_password(
        note['encrypted_content'],
        master_password
    )
    
    # Get category name if any
    category_name = "Uncategorized"
    if note['category_id']:
        category = await db.get_category(note['category_id'], user_id)
        if category:
            category_name = category['name']
    
    # Format date
    created_at = note['created_at'].strftime("%Y-%m-%d %H:%M")
    updated_at = note['updated_at'].strftime("%Y-%m-%d %H:%M") if note['updated_at'] else created_at
    
    # Log the view action
    await db.add_audit_log(
        user_id, 
        "view", 
        "secure_note", 
        note_id, 
        {"title": note['title']}
    )
    
    # Display note with options
    await callback_query.message.edit_text(
        f"📋 <b>{note['title']}</b>\n\n"
        f"{decrypted_content}\n\n"
        f"<b>Category:</b> {category_name}\n"
        f"<b>Created:</b> {created_at}\n"
        f"<b>Last Updated:</b> {updated_at}",
        reply_markup=Keyboards.secure_note_detail_keyboard(note_id),
        parse_mode=ParseMode.HTML
    )


async def update_note(callback_query: CallbackQuery, state: FSMContext):
    """Handle updating a note."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    # Extract note id
    note_id = int(callback_query.data.split("_")[-1])
    
    # Get note from database
    note = await db.get_secure_note(note_id, user_id)
    
    if not note:
        await callback_query.message.edit_text(
            "Note not found.",
            reply_markup=Keyboards.back_to_main_inline()
        )
        return
    
    # Store note id and title in state
    await state.update_data(note_id=note_id, current_title=note['title'])
    await SecureNoteStates.update_title.set()
    
    # Prompt for new title
    await callback_query.message.edit_text(
        f"✏️ <b>Update Note</b>\n\n"
        f"Current title: <b>{note['title']}</b>\n\n"
        f"Enter a new title or send the same title to keep it:",
        reply_markup=Keyboards.cancel_inline(),
        parse_mode=ParseMode.HTML
    )


async def delete_note(callback_query: CallbackQuery, state: FSMContext):
    """Handle deleting a note."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    # Extract note id
    note_id = int(callback_query.data.split("_")[-1])
    
    # Get note from database
    note = await db.get_secure_note(note_id, user_id)
    
    if not note:
        await callback_query.message.edit_text(
            "Note not found.",
            reply_markup=Keyboards.back_to_main_inline()
        )
        return
    
    # Store note id and title in state
    await state.update_data(note_id=note_id, note_title=note['title'])
    await SecureNoteStates.confirm_delete.set()
    
    # Ask for confirmation
    await callback_query.message.edit_text(
        f"🗑️ <b>Delete Note</b>\n\n"
        f"Are you sure you want to delete the note '{note['title']}'?\n\n"
        f"This action cannot be undone.",
        reply_markup=Keyboards.confirmation_keyboard(),
        parse_mode=ParseMode.HTML
    )


async def back_to_notes_list(callback_query: CallbackQuery):
    """Handle back to notes list button."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    # Get all secure notes for this user
    notes = await db.get_all_secure_notes(user_id)
    
    if not notes:
        await callback_query.message.edit_text(
            "You don't have any secure notes yet.",
            reply_markup=Keyboards.back_to_main_inline()
        )
        return
    
    # Create paginated list of notes
    page = 0
    keyboard = Keyboards.paginated_note_list(notes, page)
    
    await callback_query.message.edit_text(
        "📑 <b>Your Secure Notes</b>\n\n"
        "Select a note to view:",
        reply_markup=keyboard,
        parse_mode=ParseMode.HTML
    )


async def process_notes_pagination(callback_query: CallbackQuery):
    """Handle notes pagination."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    # Extract page number
    page = int(callback_query.data.split("_")[-1])
    
    # Get all secure notes for this user
    notes = await db.get_all_secure_notes(user_id)
    
    # Create paginated list of notes
    keyboard = Keyboards.paginated_note_list(notes, page)
    
    await callback_query.message.edit_text(
        "📑 <b>Your Secure Notes</b>\n\n"
        "Select a note to view:",
        reply_markup=keyboard,
        parse_mode=ParseMode.HTML
    )


# Password generator handlers
async def cmd_password_generator(message: types.Message):
    """Handle password generator command."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "You need to authenticate first. Use /start to begin.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    # Initialize generator options
    password_gen_options[user_id] = {
        "length": 16,
        "use_uppercase": True,
        "use_lowercase": True,
        "use_digits": True,
        "use_special": True,
        "exclude_similar": False,
        "exclude_ambiguous": False,
        "pronounceable": False
    }
    
    await message.answer(
        "🎲 <b>Password Generator</b>\n\n"
        "Configure your password generation options:",
        reply_markup=Keyboards.password_generator_keyboard(),
        parse_mode=ParseMode.HTML
    )


async def process_password_generator_options(callback_query: CallbackQuery, state: FSMContext):
    """Handle password generator options."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    data = callback_query.data
    
    if data == "set_length":
        await PasswordGeneratorStates.set_length.set()
        await callback_query.message.edit_text(
            "🔢 <b>Set Password Length</b>\n\n"
            "Please enter a number between 8 and 64:",
            reply_markup=Keyboards.cancel_inline(),
            parse_mode=ParseMode.HTML
        )
        return
    
    elif data == "generate_password":
        # Generate password
        options = password_gen_options.get(user_id, {})
        
        try:
            password = generate_password(
                length=options.get("length", 16),
                use_uppercase=options.get("use_uppercase", True),
                use_lowercase=options.get("use_lowercase", True),
                use_digits=options.get("use_digits", True),
                use_special=options.get("use_special", True),
                exclude_similar=options.get("exclude_similar", False),
                exclude_ambiguous=options.get("exclude_ambiguous", False),
                pronounceable=options.get("pronounceable", False)
            )
            
            # Calculate password strength
            strength = calculate_password_strength(password)
            
            # Format strength info
            strength_text = f"Strength: {strength['score']}/5 ({strength['rating']})"
            time_to_crack = strength.get('crack_time_display', 'unknown')
            
            # Log generation
            await db.add_audit_log(
                user_id, 
                "generate", 
                "password", 
                None, 
                {"length": options.get("length", 16)}
            )
            
            # Show the generated password
            await callback_query.message.edit_text(
                f"🎲 <b>Generated Password</b>\n\n"
                f"<code>{password}</code>\n\n"
                f"<b>{strength_text}</b>\n"
                f"Time to crack: {time_to_crack}\n\n"
                f"Press 'Generate Again' to create another password.",
                reply_markup=Keyboards.password_generator_result_keyboard(),
                parse_mode=ParseMode.HTML
            )
        except Exception as e:
            logging.error(f"Error generating password: {e}")
            await callback_query.message.edit_text(
                f"❌ Error generating password. Please try again.",
                reply_markup=Keyboards.back_to_tools_inline(),
                parse_mode=ParseMode.HTML
            )
        return
    
    # Handle toggles
    if data.startswith("toggle_"):
        option = data.replace("toggle_", "")
        options = password_gen_options.get(user_id, {})
        
        if option == "lowercase":
            options["use_lowercase"] = not options.get("use_lowercase", True)
        elif option == "uppercase":
            options["use_uppercase"] = not options.get("use_uppercase", True)
        elif option == "digits":
            options["use_digits"] = not options.get("use_digits", True)
        elif option == "special":
            options["use_special"] = not options.get("use_special", True)
        elif option == "similar":
            options["exclude_similar"] = not options.get("exclude_similar", False)
        elif option == "ambiguous":
            options["exclude_ambiguous"] = not options.get("exclude_ambiguous", False)
        elif option == "pronounceable":
            options["pronounceable"] = not options.get("pronounceable", False)
            
            # If pronounceable is enabled, disable incompatible options
            if options["pronounceable"]:
                options["use_special"] = False
        
        # Update options
        password_gen_options[user_id] = options
        
        # Update keyboard
        keyboard = Keyboards.password_generator_keyboard(
            length=options.get("length", 16),
            use_lowercase=options.get("use_lowercase", True),
            use_uppercase=options.get("use_uppercase", True),
            use_digits=options.get("use_digits", True),
            use_special=options.get("use_special", True),
            exclude_similar=options.get("exclude_similar", False),
            exclude_ambiguous=options.get("exclude_ambiguous", False),
            pronounceable=options.get("pronounceable", False)
        )
        
        await callback_query.message.edit_text(
            "🎲 <b>Password Generator</b>\n\n"
            "Configure your password generation options:",
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML
        )


async def process_password_length(message: types.Message, state: FSMContext):
    """Process password length."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        await state.finish()
        return
    
    try:
        length = int(message.text.strip())
        
        if length < 8 or length > 64:
            await message.answer(
                "❌ Password length must be between 8 and 64. Please try again:",
                reply_markup=Keyboards.cancel_keyboard()
            )
            return
        
        # Update options
        options = password_gen_options.get(user_id, {})
        options["length"] = length
        password_gen_options[user_id] = options
        
        await message.answer(
            f"✅ Password length set to {length}.",
            reply_markup=Keyboards.main_menu()
        )
        
        # Clear state
        await state.finish()
        
        # Show generator options again
        keyboard = Keyboards.password_generator_keyboard(
            length=options.get("length", 16),
            use_lowercase=options.get("use_lowercase", True),
            use_uppercase=options.get("use_uppercase", True),
            use_digits=options.get("use_digits", True),
            use_special=options.get("use_special", True),
            exclude_similar=options.get("exclude_similar", False),
            exclude_ambiguous=options.get("exclude_ambiguous", False),
            pronounceable=options.get("pronounceable", False)
        )
        
        await message.answer(
            "🎲 <b>Password Generator</b>\n\n"
            "Configure your password generation options:",
            reply_markup=keyboard,
            parse_mode=ParseMode.HTML
        )
    except ValueError:
        await message.answer(
            "❌ Invalid input. Please enter a number between 8 and 64:",
            reply_markup=Keyboards.cancel_keyboard()
        )


async def cmd_password_strength_checker(message: types.Message):
    """Handle password strength checker command."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "You need to authenticate first. Use /start to begin.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    await message.answer(
        "🔍 <b>Password Strength Checker</b>\n\n"
        "Please enter the password you want to check:\n\n"
        "<i>Note: This password will be analyzed locally and won't be stored anywhere.</i>",
        reply_markup=Keyboards.cancel_keyboard(),
        parse_mode=ParseMode.HTML
    )
    
    
async def cmd_import_passwords(message: types.Message):
    """Handle import passwords command."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "You need to authenticate first. Use /start to begin.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    await ImportExportStates.waiting_for_import_file.set()
    
    await message.answer(
        "🔄 <b>Import Passwords</b>\n\n"
        "Please send a JSON file containing the passwords you want to import.\n\n"
        "The file should be in the format:\n"
        "<code>[\n"
        "  {\n"
        "    \"service\": \"Service Name\",\n"
        "    \"username\": \"username\",\n"
        "    \"password\": \"password\",\n"
        "    \"notes\": \"Optional notes\"\n"
        "  },\n"
        "  ...\n"
        "]</code>",
        reply_markup=Keyboards.cancel_keyboard(),
        parse_mode=ParseMode.HTML
    )


async def process_import_file(message: types.Message, state: FSMContext):
    """Process import file."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        await state.finish()
        return
    
    # Check if message has document
    if not message.document:
        await message.answer(
            "❌ Please send a JSON file.",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    # Check file extension
    if not message.document.file_name.lower().endswith('.json'):
        await message.answer(
            "❌ Only JSON files are supported.",
            reply_markup=Keyboards.cancel_keyboard()
        )
        return
    
    try:
        # Download the file
        file = await message.document.download()
        
        # Read the file
        with open(file.name, 'r') as f:
            json_data = f.read()
        
        # Try to parse the JSON
        import json
        try:
            data = json.loads(json_data)
        except json.JSONDecodeError:
            await message.answer(
                "❌ Invalid JSON format. Please check your file.",
                reply_markup=Keyboards.cancel_keyboard()
            )
            return
        
        # Validate data structure
        if not isinstance(data, list):
            await message.answer(
                "❌ The JSON data should be a list of password entries.",
                reply_markup=Keyboards.cancel_keyboard()
            )
            return
        
        # Count valid entries
        valid_entries = []
        for entry in data:
            if isinstance(entry, dict) and "service" in entry and "username" in entry and "password" in entry:
                valid_entries.append(entry)
        
        # Store in state
        await state.update_data(import_data=valid_entries)
        await ImportExportStates.confirm_import.set()
        
        # Ask for confirmation
        await message.answer(
            f"📄 <b>Import Confirmation</b>\n\n"
            f"Found {len(valid_entries)} valid password entries to import.\n\n"
            f"Do you want to proceed with the import?",
            reply_markup=Keyboards.confirmation_keyboard(),
            parse_mode=ParseMode.HTML
        )
    except Exception as e:
        logging.error(f"Error processing import file: {e}")
        await message.answer(
            f"❌ Error processing file: {str(e)}",
            reply_markup=Keyboards.cancel_keyboard()
        )


async def confirm_import(callback_query: CallbackQuery, state: FSMContext):
    """Handle import confirmation."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        await state.finish()
        return
    
    if callback_query.data == "confirm_yes":
        # Get data from state
        data = await state.get_data()
        import_data = data.get("import_data", [])
        
        if not import_data:
            await callback_query.message.edit_text(
                "❌ No valid data to import.",
                reply_markup=Keyboards.back_to_main_inline()
            )
            await state.finish()
            return
        
        # Get master password from session
        master_password = session.master_password
        
        # Import passwords
        success_count = 0
        for entry in import_data:
            service_name = entry.get("service", "").strip()
            username = entry.get("username", "").strip()
            password = entry.get("password", "")
            notes = entry.get("notes", "")
            
            # Skip invalid entries
            if not service_name or not username or not password:
                continue
            
            # Encrypt password
            encrypted_password = PasswordEncryption.encrypt_password(password, master_password)
            
            # Add to database
            password_id = await db.add_password(
                user_id, 
                service_name, 
                username, 
                encrypted_password, 
                notes
            )
            
            if password_id:
                success_count += 1
        
        # Log the import
        await db.add_audit_log(
            user_id, 
            "import", 
            "passwords", 
            None, 
            {"count": success_count}
        )
        
        # Show result
        await callback_query.message.edit_text(
            f"✅ Successfully imported {success_count} out of {len(import_data)} passwords.",
            reply_markup=Keyboards.back_to_main_inline()
        )
    else:
        # User canceled the operation
        await callback_query.message.edit_text(
            "❌ Import canceled.",
            reply_markup=Keyboards.back_to_main_inline()
        )
    
    # Clear state
    await state.finish()


async def cmd_export_data(message: types.Message):
    """Handle export data command."""
    user_id = message.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await message.answer(
            "You need to authenticate first. Use /start to begin.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        return
    
    await ImportExportStates.select_export_format.set()
    
    await message.answer(
        "📤 <b>Export Data</b>\n\n"
        "Select the export format:",
        reply_markup=Keyboards.export_format_keyboard(),
        parse_mode=ParseMode.HTML
    )


async def export_data_format(callback_query: CallbackQuery, state: FSMContext):
    """Handle export format selection."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        await state.finish()
        return
    
    if callback_query.data == "export_format_json":
        # Store format in state
        await state.update_data(export_format="json")
        await ImportExportStates.select_export_type.set()
        
        # Ask for data type
        await callback_query.message.edit_text(
            "📤 <b>Export Data</b>\n\n"
            "Select what you want to export:",
            reply_markup=Keyboards.export_type_keyboard(),
            parse_mode=ParseMode.HTML
        )
    else:
        # Back to main
        await callback_query.message.edit_text(
            "❌ Export canceled.",
            reply_markup=Keyboards.back_to_main_inline()
        )
        await state.finish()


async def export_data_type(callback_query: CallbackQuery, state: FSMContext):
    """Handle export type selection."""
    await callback_query.answer()
    
    user_id = callback_query.from_user.id
    session = get_user_session(user_id)
    
    if not session.is_authenticated():
        await callback_query.message.answer(
            "Your session has expired. Please authenticate again.",
            reply_markup=types.ReplyKeyboardRemove()
        )
        await state.finish()
        return
    
    if callback_query.data.startswith("export_type_"):
        export_type = callback_query.data.replace("export_type_", "")
        
        # Get data from database
        master_password = session.master_password
        passwords = []
        notes = []
        
        if export_type in ["passwords", "all"]:
            # Get all passwords
            encrypted_passwords = await db.get_all_passwords(user_id)
            
            # Decrypt passwords
            for p in encrypted_passwords:
                p_copy = p.copy()
                p_copy["password"] = PasswordEncryption.decrypt_password(
                    p["encrypted_password"],
                    master_password
                )
                p_copy.pop("encrypted_password", None)
                passwords.append(p_copy)
        
        if export_type in ["notes", "all"]:
            # Get all notes
            encrypted_notes = await db.get_all_secure_notes(user_id)
            
            # Decrypt notes
            for n in encrypted_notes:
                n_copy = n.copy()
                n_copy["content"] = PasswordEncryption.decrypt_password(
                    n["encrypted_content"],
                    master_password
                )
                n_copy.pop("encrypted_content", None)
                notes.append(n_copy)
        
        # Generate export data
        import json
        
        if export_type == "passwords":
            export_data = json.dumps(passwords, indent=2)
            filename = f"passwords_export_{user_id}.json"
        elif export_type == "notes":
            export_data = json.dumps(notes, indent=2)
            filename = f"notes_export_{user_id}.json"
        else:  # all
            export_data = json.dumps({
                "passwords": passwords,
                "notes": notes
            }, indent=2)
            filename = f"data_export_{user_id}.json"
        
        # Create temporary file
        import tempfile
        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w+', suffix='.json')
        temp_file.write(export_data)
        temp_file.close()
        
        # Log the export
        await db.add_audit_log(
            user_id, 
            "export", 
            export_type, 
            None, 
            {"count": len(passwords) if export_type == "passwords" else 
                     len(notes) if export_type == "notes" else 
                     len(passwords) + len(notes)}
        )
        
        # Send the file
        with open(temp_file.name, 'rb') as f:
            await callback_query.message.answer_document(
                document=types.InputFile(f, filename=filename),
                caption=f"✅ Export completed successfully.\n\n"
                       f"Contents: {len(passwords)} passwords"
                       f"{' and ' + str(len(notes)) + ' notes' if export_type in ['notes', 'all'] else ''}."
            )
        
        # Send a message with back button
        await callback_query.message.edit_text(
            "✅ Export completed.",
            reply_markup=Keyboards.back_to_main_inline()
        )
    else:
        # Back to tools
        await callback_query.message.edit_text(
            "❌ Export canceled.",
            reply_markup=Keyboards.back_to_tools_inline()
        )
    
    # Clear state
    await state.finish()


# Dictionary to store user sessions
user_sessions = {}

# Dictionary to store password generation options
password_gen_options = {}


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
        "• Organize passwords with categories\n"
        "• Add, view, update, and delete passwords\n"
        "• Create and manage secure notes\n"
        "• Search for passwords by service or username\n"
        "• Generate strong random passwords\n"
        "• Share passwords with other users\n"
        "• Import and export your data\n"
        "• Change your master password\n\n"
        
        "<b>Security:</b>\n"
        "• All sensitive data is encrypted with your master password\n"
        "• Your master password is never stored in plain text\n"
        "• Data is only decrypted when you need it\n"
        "• Session automatically expires after inactivity\n\n"
        
        "<b>Tips:</b>\n"
        "• Use a strong, unique master password\n"
        "• Don't forget your master password - it cannot be recovered!\n"
        "• Use the 'Generate' option to create strong passwords\n"
        "• Organize passwords in categories for easy access\n"
        "• Use secure notes for storing sensitive text information\n"
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
    
    # Category handlers
    dp.register_message_handler(cmd_categories, Text(equals="📁 Categories"))
    dp.register_callback_query_handler(process_category_action, lambda c: c.data.startswith("category_"))
    dp.register_callback_query_handler(manage_categories, lambda c: c.data == "manage_categories")
    dp.register_callback_query_handler(add_category, lambda c: c.data == "add_category")
    dp.register_callback_query_handler(edit_category, lambda c: c.data.startswith("edit_category_"))
    dp.register_callback_query_handler(delete_category, lambda c: c.data.startswith("delete_category_"))
    dp.register_callback_query_handler(back_to_categories, lambda c: c.data == "back_to_categories")
    dp.register_message_handler(process_category_name, state=CategoryStates.add_category)
    dp.register_message_handler(process_edit_category_name, state=CategoryStates.edit_category)
    dp.register_callback_query_handler(process_delete_category, lambda c: c.data.startswith("confirm_delete_category_"), state=CategoryStates.delete_category)
    
    # Secure note handlers
    dp.register_message_handler(cmd_add_note, Text(equals="📋 Add Note"))
    dp.register_message_handler(cmd_view_notes, Text(equals="📑 View Notes"))
    dp.register_message_handler(process_note_title, state=SecureNoteStates.waiting_for_title)
    dp.register_message_handler(process_note_content, state=SecureNoteStates.waiting_for_content)
    dp.register_callback_query_handler(confirm_add_note, lambda c: c.data.startswith("confirm_"), state=SecureNoteStates.confirm_add)
    dp.register_callback_query_handler(view_note, lambda c: c.data.startswith("view_note_"))
    dp.register_callback_query_handler(update_note, lambda c: c.data.startswith("update_note_"))
    dp.register_callback_query_handler(delete_note, lambda c: c.data.startswith("delete_note_"))
    dp.register_callback_query_handler(back_to_notes_list, lambda c: c.data == "back_to_notes_list")
    dp.register_callback_query_handler(process_notes_pagination, lambda c: c.data.startswith("notes_page_"))
    
    # Tools menu handlers
    dp.register_message_handler(cmd_tools, Text(equals="⚒️ Tools"))
    dp.register_message_handler(cmd_password_generator, Text(equals="🎲 Password Generator"))
    dp.register_message_handler(cmd_import_passwords, Text(equals="🔄 Import Passwords"))
    dp.register_message_handler(cmd_export_data, Text(equals="📤 Export Data"))
    dp.register_message_handler(cmd_password_strength_checker, Text(equals="🔍 Password Strength Checker"))
    dp.register_callback_query_handler(process_password_generator_options, lambda c: c.data.startswith(("toggle_", "set_length", "generate_password")))
    dp.register_message_handler(process_password_length, state=PasswordGeneratorStates.set_length)
    dp.register_message_handler(process_import_file, state=ImportExportStates.waiting_for_import_file)
    dp.register_callback_query_handler(confirm_import, lambda c: c.data.startswith("confirm_"), state=ImportExportStates.confirm_import)
    dp.register_callback_query_handler(export_data_format, lambda c: c.data.startswith("export_format_"), state=ImportExportStates.select_export_format)
    dp.register_callback_query_handler(export_data_type, lambda c: c.data.startswith("export_type_"), state=ImportExportStates.select_export_type)
    
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
    
    # Tools handlers
    dp.register_message_handler(cmd_tools, Text(equals="⚒️ Tools"))
    
    # Password generator handlers
    dp.register_message_handler(cmd_password_generator, Text(equals="🎲 Password Generator"))
    dp.register_callback_query_handler(
        process_password_generator_options,
        lambda c: c.data.startswith("toggle_") or c.data == "set_length" or c.data == "generate_password"
    )
    dp.register_message_handler(
        process_password_length,
        state=PasswordGeneratorStates.set_length
    )
    
    # Password strength checker
    dp.register_message_handler(cmd_password_strength_checker, Text(equals="🔍 Password Strength Checker"))
    
    # Import/Export handlers
    dp.register_message_handler(cmd_import_passwords, Text(equals="🔄 Import Passwords"))
    dp.register_message_handler(cmd_export_data, Text(equals="📤 Export Data"))
    dp.register_message_handler(
        process_import_file, 
        content_types=types.ContentTypes.DOCUMENT,
        state=ImportExportStates.waiting_for_import_file
    )
    dp.register_callback_query_handler(
        confirm_import,
        lambda c: c.data.startswith("confirm_"),
        state=ImportExportStates.confirm_import
    )
    dp.register_callback_query_handler(
        export_data_format,
        lambda c: c.data.startswith("export_format_"),
        state=ImportExportStates.select_export_format
    )
    dp.register_callback_query_handler(
        export_data_type,
        lambda c: c.data.startswith("export_type_"),
        state=ImportExportStates.select_export_type
    )
    
    # Secure Notes handlers
    dp.register_message_handler(cmd_add_note, Text(equals="📝 Add Note"))
    dp.register_message_handler(cmd_view_notes, Text(equals="📑 View Notes"))
    dp.register_message_handler(
        process_note_title,
        state=SecureNoteStates.waiting_for_title
    )
    dp.register_message_handler(
        process_note_content,
        state=SecureNoteStates.waiting_for_content
    )
    dp.register_callback_query_handler(
        confirm_add_note,
        lambda c: c.data.startswith("confirm_"),
        state=SecureNoteStates.confirm_add
    )
    dp.register_callback_query_handler(
        view_note,
        lambda c: c.data.startswith("view_note_")
    )
    dp.register_callback_query_handler(
        update_note,
        lambda c: c.data.startswith("update_note_")
    )
    dp.register_callback_query_handler(
        delete_note,
        lambda c: c.data.startswith("delete_note_")
    )
    dp.register_callback_query_handler(
        back_to_notes_list,
        lambda c: c.data == "back_to_notes"
    )
    dp.register_callback_query_handler(
        process_notes_pagination,
        lambda c: c.data.startswith("notes_page_")
    )
