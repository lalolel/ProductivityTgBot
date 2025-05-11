import re
import random
import string
import logging
from typing import Dict, Optional, Any, Tuple


def validate_master_password(password: str, min_length: int = 8) -> Tuple[bool, str]:
    """
    Validate master password strength.
    
    Args:
        password: The password to validate
        min_length: Minimum password length
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < min_length:
        return False, f"Password must be at least {min_length} characters long"
    
    # Check for at least one uppercase letter
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    # Check for at least one lowercase letter
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    # Check for at least one digit
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    
    # Check for at least one special character
    if not any(c in string.punctuation for c in password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"


def validate_service_name(service_name: str) -> Tuple[bool, str]:
    """
    Validate service name.
    
    Args:
        service_name: The service name to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not service_name:
        return False, "Service name cannot be empty"
    
    if len(service_name) > 255:
        return False, "Service name cannot exceed 255 characters"
    
    return True, "Service name is valid"


def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validate username.
    
    Args:
        username: The username to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not username:
        return False, "Username cannot be empty"
    
    if len(username) > 255:
        return False, "Username cannot exceed 255 characters"
    
    return True, "Username is valid"


def generate_password(length: int = 16, 
                      use_uppercase: bool = True, 
                      use_lowercase: bool = True,
                      use_digits: bool = True,
                      use_special: bool = True) -> str:
    """
    Generate a strong random password.
    
    Args:
        length: Password length
        use_uppercase: Include uppercase letters
        use_lowercase: Include lowercase letters
        use_digits: Include digits
        use_special: Include special characters
        
    Returns:
        Generated password
    """
    chars = ''
    
    if use_lowercase:
        chars += string.ascii_lowercase
    if use_uppercase:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_special:
        chars += string.punctuation
    
    if not chars:
        # Default to lowercase if nothing is selected
        chars = string.ascii_lowercase
    
    # Ensure the password has at least one character from each selected category
    password = []
    
    if use_lowercase:
        password.append(random.choice(string.ascii_lowercase))
    if use_uppercase:
        password.append(random.choice(string.ascii_uppercase))
    if use_digits:
        password.append(random.choice(string.digits))
    if use_special:
        password.append(random.choice(string.punctuation))
    
    # Fill the rest of the password
    remaining_length = length - len(password)
    password.extend(random.choice(chars) for _ in range(remaining_length))
    
    # Shuffle the password
    random.shuffle(password)
    
    return ''.join(password)


def format_password_details(password_data: Dict[str, Any], 
                            show_password: bool = False,
                            decrypted_password: Optional[str] = None) -> str:
    """
    Format password details for display.
    
    Args:
        password_data: Password data dictionary
        show_password: Whether to show the actual password
        decrypted_password: The decrypted password if available
        
    Returns:
        Formatted password details as a string
    """
    service = password_data['service_name']
    username = password_data['username']
    notes = password_data.get('notes', '')
    
    # Format the message
    message = (
        f"🔐 <b>{service}</b>\n\n"
        f"👤 <b>Username:</b> {username}\n"
    )
    
    if show_password and decrypted_password:
        message += f"🔑 <b>Password:</b> <code>{decrypted_password}</code>\n"
    else:
        message += f"🔑 <b>Password:</b> <i>*********</i>\n"
    
    if notes:
        message += f"\n📝 <b>Notes:</b>\n{notes}\n"
    
    return message


def sanitize_input(text: str) -> str:
    """
    Sanitize user input to prevent any potential injection attacks.
    
    Args:
        text: User input text
        
    Returns:
        Sanitized text
    """
    if not text:
        return ""
    
    # Remove any potentially harmful characters
    sanitized = re.sub(r'[^\w\s\-_.,@!?#$%^&*()[\]{}:;<>+=/\\|"\'`~]', '', text)
    
    return sanitized.strip()
