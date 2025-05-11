from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, ReplyKeyboardMarkup, KeyboardButton
from typing import List, Dict, Optional

class Keyboards:
    """Class for creating bot keyboards."""
    
    @staticmethod
    def main_menu() -> ReplyKeyboardMarkup:
        """Create main menu keyboard."""
        keyboard = ReplyKeyboardMarkup(resize_keyboard=True)
        keyboard.add(KeyboardButton("📁 Categories"))
        keyboard.add(KeyboardButton("📝 Add Password"), KeyboardButton("📋 Add Note"))
        keyboard.add(KeyboardButton("🔍 View Passwords"), KeyboardButton("📑 View Notes")) 
        keyboard.add(KeyboardButton("🔎 Search"), KeyboardButton("⚒️ Tools"))
        keyboard.add(KeyboardButton("⚙️ Settings"), KeyboardButton("ℹ️ Help"))
        return keyboard
    
    @staticmethod
    def cancel_keyboard() -> ReplyKeyboardMarkup:
        """Create cancel keyboard."""
        keyboard = ReplyKeyboardMarkup(resize_keyboard=True)
        keyboard.add(KeyboardButton("❌ Cancel"))
        return keyboard

    @staticmethod
    def settings_keyboard() -> ReplyKeyboardMarkup:
        """Create settings keyboard."""
        keyboard = ReplyKeyboardMarkup(resize_keyboard=True)
        keyboard.add(KeyboardButton("🔑 Change Master Password"))
        keyboard.add(KeyboardButton("🗑 Delete Account"))
        keyboard.add(KeyboardButton("⬅️ Back to Main Menu"))
        return keyboard
    
    @staticmethod
    def confirmation_keyboard() -> InlineKeyboardMarkup:
        """Create confirmation keyboard."""
        keyboard = InlineKeyboardMarkup(row_width=2)
        keyboard.add(
            InlineKeyboardButton("Yes", callback_data="confirm_yes"),
            InlineKeyboardButton("No", callback_data="confirm_no")
        )
        return keyboard
    
    @staticmethod
    def password_list_keyboard(passwords: List[Dict]) -> InlineKeyboardMarkup:
        """Create keyboard with list of passwords."""
        keyboard = InlineKeyboardMarkup(row_width=1)
        
        for password in passwords:
            button_text = f"{password['service_name']} ({password['username']})"
            callback_data = f"view_password_{password['id']}"
            keyboard.add(InlineKeyboardButton(button_text, callback_data=callback_data))
        
        if passwords:
            keyboard.add(InlineKeyboardButton("⬅️ Back", callback_data="back_to_main"))
        
        return keyboard
    
    @staticmethod
    def paginated_password_list(passwords: List[Dict], page: int = 0, 
                                page_size: int = 5) -> InlineKeyboardMarkup:
        """Create paginated keyboard with list of passwords."""
        keyboard = InlineKeyboardMarkup(row_width=1)
        
        # Calculate pagination
        total_pages = (len(passwords) + page_size - 1) // page_size
        start_idx = page * page_size
        end_idx = min(start_idx + page_size, len(passwords))
        
        # Add password buttons for current page
        for password in passwords[start_idx:end_idx]:
            button_text = f"{password['service_name']} ({password['username']})"
            callback_data = f"view_password_{password['id']}"
            keyboard.add(InlineKeyboardButton(button_text, callback_data=callback_data))
        
        # Add pagination navigation if needed
        nav_buttons = []
        
        if page > 0:
            nav_buttons.append(InlineKeyboardButton("⬅️ Prev", callback_data=f"page_{page-1}"))
        
        if page < total_pages - 1:
            nav_buttons.append(InlineKeyboardButton("Next ➡️", callback_data=f"page_{page+1}"))
        
        if nav_buttons:
            keyboard.row(*nav_buttons)
        
        # Add back button
        keyboard.add(InlineKeyboardButton("⬅️ Back to Main", callback_data="back_to_main"))
        
        return keyboard
    
    @staticmethod
    def password_detail_keyboard(password_id: int) -> InlineKeyboardMarkup:
        """Create keyboard for password detail view."""
        keyboard = InlineKeyboardMarkup(row_width=2)
        
        # Add action buttons
        keyboard.add(
            InlineKeyboardButton("🔄 Update", callback_data=f"update_password_{password_id}"),
            InlineKeyboardButton("🗑 Delete", callback_data=f"delete_password_{password_id}")
        )
        
        # Add show/hide password button
        keyboard.add(InlineKeyboardButton("👁 Show Password", callback_data=f"show_password_{password_id}"))
        
        # Add back button
        keyboard.add(InlineKeyboardButton("⬅️ Back to List", callback_data="back_to_list"))
        
        return keyboard
    
    @staticmethod
    def hide_password_keyboard(password_id: int) -> InlineKeyboardMarkup:
        """Create keyboard with hide password button."""
        keyboard = InlineKeyboardMarkup()
        keyboard.add(InlineKeyboardButton("🔒 Hide Password", callback_data=f"hide_password_{password_id}"))
        return keyboard
        
    @staticmethod
    def tools_keyboard() -> ReplyKeyboardMarkup:
        """Create tools keyboard."""
        keyboard = ReplyKeyboardMarkup(resize_keyboard=True)
        keyboard.add(KeyboardButton("🔄 Import Passwords"), KeyboardButton("📤 Export Data"))
        keyboard.add(KeyboardButton("🎲 Password Generator"))
        keyboard.add(KeyboardButton("🔍 Password Strength Checker"))
        keyboard.add(KeyboardButton("⬅️ Back to Main Menu"))
        return keyboard
        
    @staticmethod
    def categories_keyboard(categories: List[Dict], include_all: bool = True) -> InlineKeyboardMarkup:
        """Create keyboard with list of categories."""
        keyboard = InlineKeyboardMarkup(row_width=1)
        
        # Add "All" option if requested
        if include_all:
            keyboard.add(InlineKeyboardButton("📂 All Items", callback_data="category_all"))
        
        # Add "Uncategorized" option
        keyboard.add(InlineKeyboardButton("📂 Uncategorized", callback_data="category_none"))
        
        # Add category buttons
        for category in categories:
            button_text = f"📂 {category['name']}"
            callback_data = f"category_{category['id']}"
            keyboard.add(InlineKeyboardButton(button_text, callback_data=callback_data))
        
        # Add manage categories button
        keyboard.add(InlineKeyboardButton("⚙️ Manage Categories", callback_data="manage_categories"))
        
        # Add back button
        keyboard.add(InlineKeyboardButton("⬅️ Back", callback_data="back_to_main"))
        
        return keyboard
        
    @staticmethod
    def manage_categories_keyboard(categories: List[Dict]) -> InlineKeyboardMarkup:
        """Create keyboard for managing categories."""
        keyboard = InlineKeyboardMarkup(row_width=2)
        
        # Add new category button
        keyboard.add(InlineKeyboardButton("➕ Add New Category", callback_data="add_category"))
        
        # Add category buttons with edit/delete options
        for category in categories:
            # Add a row for each category
            keyboard.add(
                InlineKeyboardButton(f"{category['name']}", callback_data=f"category_info_{category['id']}"),
                InlineKeyboardButton("✏️", callback_data=f"edit_category_{category['id']}"),
                InlineKeyboardButton("🗑️", callback_data=f"delete_category_{category['id']}")
            )
        
        # Add back button
        keyboard.add(InlineKeyboardButton("⬅️ Back", callback_data="back_to_categories"))
        
        return keyboard
        
    @staticmethod
    def secure_note_list_keyboard(notes: List[Dict]) -> InlineKeyboardMarkup:
        """Create keyboard with list of secure notes."""
        keyboard = InlineKeyboardMarkup(row_width=1)
        
        for note in notes:
            button_text = f"{note['title']}"
            callback_data = f"view_note_{note['id']}"
            keyboard.add(InlineKeyboardButton(button_text, callback_data=callback_data))
        
        if notes:
            keyboard.add(InlineKeyboardButton("⬅️ Back", callback_data="back_to_main"))
        
        return keyboard
        
    @staticmethod
    def paginated_note_list(notes: List[Dict], page: int = 0, 
                           page_size: int = 5) -> InlineKeyboardMarkup:
        """Create paginated keyboard with list of secure notes."""
        keyboard = InlineKeyboardMarkup(row_width=1)
        
        # Calculate pagination
        total_pages = (len(notes) + page_size - 1) // page_size
        start_idx = page * page_size
        end_idx = min(start_idx + page_size, len(notes))
        
        # Add note buttons for current page
        for note in notes[start_idx:end_idx]:
            button_text = f"{note['title']}"
            callback_data = f"view_note_{note['id']}"
            keyboard.add(InlineKeyboardButton(button_text, callback_data=callback_data))
        
        # Add pagination navigation if needed
        nav_buttons = []
        
        if page > 0:
            nav_buttons.append(InlineKeyboardButton("⬅️ Prev", callback_data=f"notes_page_{page-1}"))
        
        if page < total_pages - 1:
            nav_buttons.append(InlineKeyboardButton("Next ➡️", callback_data=f"notes_page_{page+1}"))
        
        if nav_buttons:
            keyboard.row(*nav_buttons)
        
        # Add back button
        keyboard.add(InlineKeyboardButton("⬅️ Back to Main", callback_data="back_to_main"))
        
        return keyboard
        
    @staticmethod
    def secure_note_detail_keyboard(note_id: int) -> InlineKeyboardMarkup:
        """Create keyboard for secure note detail view."""
        keyboard = InlineKeyboardMarkup(row_width=2)
        
        # Add action buttons
        keyboard.add(
            InlineKeyboardButton("🔄 Update", callback_data=f"update_note_{note_id}"),
            InlineKeyboardButton("🗑 Delete", callback_data=f"delete_note_{note_id}")
        )
        
        # Add back button
        keyboard.add(InlineKeyboardButton("⬅️ Back to List", callback_data="back_to_notes_list"))
        
        return keyboard
        
    @staticmethod
    def password_generator_keyboard() -> InlineKeyboardMarkup:
        """Create keyboard for password generator options."""
        keyboard = InlineKeyboardMarkup(row_width=1)
        
        keyboard.add(
            InlineKeyboardButton("Length: 16", callback_data="set_length")
        )
        
        # Add toggle options
        keyboard.row(
            InlineKeyboardButton("🔤 a-z: ON", callback_data="toggle_lowercase"),
            InlineKeyboardButton("🔠 A-Z: ON", callback_data="toggle_uppercase")
        )
        
        keyboard.row(
            InlineKeyboardButton("🔢 0-9: ON", callback_data="toggle_digits"),
            InlineKeyboardButton("🔣 &$#: ON", callback_data="toggle_special")
        )
        
        keyboard.row(
            InlineKeyboardButton("Similar: OFF", callback_data="toggle_similar"),
            InlineKeyboardButton("Ambiguous: OFF", callback_data="toggle_ambiguous")
        )
        
        keyboard.add(
            InlineKeyboardButton("Pronounceable: OFF", callback_data="toggle_pronounceable")
        )
        
        # Add generate button
        keyboard.add(
            InlineKeyboardButton("🎲 Generate Password", callback_data="generate_password")
        )
        
        return keyboard
        
    @staticmethod
    def password_share_keyboard(password_id: int) -> InlineKeyboardMarkup:
        """Create keyboard for sharing password."""
        keyboard = InlineKeyboardMarkup(row_width=1)
        
        keyboard.add(
            InlineKeyboardButton("📤 Share Password", callback_data=f"share_password_{password_id}")
        )
        
        # Add expiration options
        keyboard.add(
            InlineKeyboardButton("Set Expiration", callback_data=f"set_expiration_{password_id}")
        )
        
        keyboard.add(
            InlineKeyboardButton("⬅️ Back", callback_data=f"back_to_password_{password_id}")
        )
        
        return keyboard
        
    @staticmethod
    def shared_passwords_keyboard(shared_passwords: List[Dict]) -> InlineKeyboardMarkup:
        """Create keyboard with list of shared passwords."""
        keyboard = InlineKeyboardMarkup(row_width=1)
        
        for shared in shared_passwords:
            button_text = f"{shared['service_name']} (shared by {shared['shared_by_username']})"
            callback_data = f"view_shared_{shared['id']}"
            keyboard.add(InlineKeyboardButton(button_text, callback_data=callback_data))
        
        keyboard.add(
            InlineKeyboardButton("⬅️ Back", callback_data="back_to_main")
        )
        
        return keyboard
        
    @staticmethod
    def back_to_categories_inline() -> InlineKeyboardMarkup:
        """Create back to categories button as inline keyboard."""
        keyboard = InlineKeyboardMarkup()
        keyboard.add(InlineKeyboardButton("⬅️ Back to Categories", callback_data="back_to_categories"))
        return keyboard
        
    @staticmethod
    def confirm_delete_category_keyboard(category_id: int) -> InlineKeyboardMarkup:
        """Create confirmation keyboard for category deletion."""
        keyboard = InlineKeyboardMarkup(row_width=2)
        keyboard.add(
            InlineKeyboardButton("Yes", callback_data=f"confirm_delete_category_yes_{category_id}"),
            InlineKeyboardButton("No", callback_data=f"confirm_delete_category_no_{category_id}")
        )
        return keyboard
        
    @staticmethod
    def export_format_keyboard() -> InlineKeyboardMarkup:
        """Create keyboard for export format selection."""
        keyboard = InlineKeyboardMarkup(row_width=1)
        keyboard.add(
            InlineKeyboardButton("JSON (recommended)", callback_data="export_format_json")
        )
        keyboard.add(
            InlineKeyboardButton("⬅️ Cancel", callback_data="back_to_main")
        )
        return keyboard
        
    @staticmethod
    def export_type_keyboard() -> InlineKeyboardMarkup:
        """Create keyboard for export type selection."""
        keyboard = InlineKeyboardMarkup(row_width=1)
        keyboard.add(
            InlineKeyboardButton("Passwords Only", callback_data="export_type_passwords")
        )
        keyboard.add(
            InlineKeyboardButton("Notes Only", callback_data="export_type_notes")
        )
        keyboard.add(
            InlineKeyboardButton("Everything", callback_data="export_type_all")
        )
        keyboard.add(
            InlineKeyboardButton("⬅️ Back", callback_data="back_to_tools")
        )
        return keyboard
