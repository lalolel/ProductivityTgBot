from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, ReplyKeyboardMarkup, KeyboardButton
from typing import List, Dict

class Keyboards:
    """Class for creating bot keyboards."""
    
    @staticmethod
    def main_menu() -> ReplyKeyboardMarkup:
        """Create main menu keyboard."""
        keyboard = ReplyKeyboardMarkup(resize_keyboard=True)
        keyboard.add(KeyboardButton("📝 Add Password"))
        keyboard.add(KeyboardButton("🔍 View Passwords"), KeyboardButton("🔎 Search"))
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
