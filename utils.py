import re
import random
import string
import logging
import json
from typing import Dict, Optional, Any, Tuple, List


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
                      use_special: bool = True,
                      exclude_similar: bool = False,
                      exclude_ambiguous: bool = False,
                      pronounceable: bool = False) -> str:
    """
    Generate a strong random password with enhanced options.
    
    Args:
        length: Password length
        use_uppercase: Include uppercase letters
        use_lowercase: Include lowercase letters
        use_digits: Include digits
        use_special: Include special characters
        exclude_similar: Exclude similar characters like 'l', '1', 'I', '0', 'O'
        exclude_ambiguous: Exclude ambiguous characters like '{', '}', '[', ']', '(', ')', '/', '\', etc.
        pronounceable: Generate a pronounceable password (overrides other character set options)
        
    Returns:
        Generated password
    """
    if pronounceable:
        return generate_pronounceable_password(length)
    
    # Define character sets
    lowercase_chars = string.ascii_lowercase
    uppercase_chars = string.ascii_uppercase
    digit_chars = string.digits
    special_chars = string.punctuation
    
    # Handle exclusions
    if exclude_similar:
        similar_chars = 'Il1O0o'
        lowercase_chars = ''.join(c for c in lowercase_chars if c not in similar_chars)
        uppercase_chars = ''.join(c for c in uppercase_chars if c not in similar_chars)
        digit_chars = ''.join(c for c in digit_chars if c not in similar_chars)
    
    if exclude_ambiguous:
        ambiguous_chars = '{}[]()<>/\\\'"`~,;:.|'
        special_chars = ''.join(c for c in special_chars if c not in ambiguous_chars)
    
    # Build character pool
    chars = ''
    if use_lowercase:
        chars += lowercase_chars
    if use_uppercase:
        chars += uppercase_chars
    if use_digits:
        chars += digit_chars
    if use_special:
        chars += special_chars
    
    if not chars:
        # Default to lowercase if nothing is selected
        chars = lowercase_chars
    
    # Ensure the password has at least one character from each selected category
    # if there's enough length
    password = []
    required_categories = []
    
    if use_lowercase and lowercase_chars:
        required_categories.append(lowercase_chars)
    if use_uppercase and uppercase_chars:
        required_categories.append(uppercase_chars)
    if use_digits and digit_chars:
        required_categories.append(digit_chars)
    if use_special and special_chars:
        required_categories.append(special_chars)
    
    # If password is shorter than number of required categories, 
    # we can't include all categories
    for category in required_categories[:min(length, len(required_categories))]:
        password.append(random.choice(category))
    
    # Fill the rest of the password
    remaining_length = length - len(password)
    if remaining_length > 0:
        password.extend(random.choice(chars) for _ in range(remaining_length))
    
    # Shuffle the password
    random.shuffle(password)
    
    return ''.join(password)


def generate_pronounceable_password(length: int = 16) -> str:
    """
    Generate a pronounceable password using consonant-vowel patterns.
    
    Args:
        length: Password length
        
    Returns:
        Generated pronounceable password
    """
    vowels = 'aeiouy'
    consonants = 'bcdfghjklmnpqrstvwxz'
    
    # Include some digits and special chars for better security
    digits = '23456789'  # Excluding 0 and 1 to avoid confusion
    special = '@#$%&*+-='
    
    password = []
    
    # Build password with alternating consonant-vowel pattern for pronounceability
    i = 0
    while len(password) < length:
        if i % 2 == 0:
            # Add a consonant or (rarely) a digit
            if random.random() < 0.9 or len(password) >= length - 2:
                password.append(random.choice(consonants))
            else:
                password.append(random.choice(digits))
        else:
            # Add a vowel or (very rarely) a special character
            if random.random() < 0.95 or len(password) >= length - 2:
                password.append(random.choice(vowels))
            else:
                password.append(random.choice(special))
        i += 1
    
    # Capitalize some characters (about 1/4 of the password)
    for i in range(length // 4):
        index = random.randint(0, length - 1)
        if password[index].isalpha():
            password[index] = password[index].upper()
    
    # Ensure we have at least one digit and one special character
    # if the password is long enough
    if length >= 8:
        # Replace a random character with a digit
        index = random.randint(0, length - 1)
        password[index] = random.choice(digits)
        
        # Replace another random character with a special character
        index = random.randint(0, length - 1)
        password[index] = random.choice(special)
    
    return ''.join(password)


def calculate_password_strength(password: str) -> Dict[str, Any]:
    """
    Calculate the strength of a password.
    
    Args:
        password: The password to analyze
        
    Returns:
        Dictionary with strength details
    """
    # Initialize score
    score = 0
    feedback = []
    
    # Basic checks
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password is too short")
    
    # Check character types
    has_lowercase = any(c.islower() for c in password)
    has_uppercase = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    character_type_count = sum([has_lowercase, has_uppercase, has_digit, has_special])
    score += character_type_count
    
    if not has_lowercase:
        feedback.append("Add lowercase letters")
    if not has_uppercase:
        feedback.append("Add uppercase letters")
    if not has_digit:
        feedback.append("Add numbers")
    if not has_special:
        feedback.append("Add special characters")
    
    # Check for common patterns
    # Check for sequential characters
    sequences = [
        ''.join(str(i) for i in range(10)), 
        string.ascii_lowercase, 
        string.ascii_uppercase
    ]
    
    for seq in sequences:
        for i in range(len(seq) - 2):
            if seq[i:i+3] in password:
                score -= 1
                feedback.append("Avoid sequences like '{}''".format(seq[i:i+3]))
                break
    
    # Check for repeated characters
    if any(c * 3 in password for c in password):
        score -= 1
        feedback.append("Avoid repeated characters")
    
    # Calculate strength level
    if score <= 2:
        strength = "Very weak"
    elif score <= 4:
        strength = "Weak"
    elif score <= 6:
        strength = "Moderate"
    elif score <= 8:
        strength = "Strong"
    else:
        strength = "Very strong"
    
    return {
        "score": score,
        "strength": strength,
        "feedback": feedback
    }


def import_passwords_from_json(json_data: str, master_password: str, salt: str) -> List[Dict]:
    """
    Import passwords from a JSON string.
    
    Args:
        json_data: JSON-formatted string containing passwords
        master_password: Master password for encryption
        salt: Salt for encryption
        
    Returns:
        List of password dictionaries ready to be added to the database
    """
    try:
        from encryption import PasswordEncryption
        
        # Parse JSON
        data = json.loads(json_data)
        passwords = []
        
        for item in data:
            # Validate required fields
            if 'service_name' not in item or 'username' not in item or 'password' not in item:
                continue
            
            # Create a new password entry
            password_entry = {
                'service_name': item.get('service_name', ''),
                'username': item.get('username', ''),
                'encrypted_password': PasswordEncryption.encrypt_password(
                    item.get('password', ''),
                    master_password,
                    salt
                ),
                'notes': item.get('notes', None),
                'category_id': None  # Default to no category
            }
            
            # Try to extract category name if provided
            if 'category' in item and item['category']:
                password_entry['category_name'] = item['category']
            
            # Add custom fields if provided
            if 'custom_fields' in item and isinstance(item['custom_fields'], dict):
                custom_fields = []
                for field_name, field_value in item['custom_fields'].items():
                    if field_name and field_value:
                        custom_fields.append({
                            'field_name': field_name,
                            'encrypted_value': PasswordEncryption.encrypt_password(
                                field_value,
                                master_password,
                                salt
                            )
                        })
                if custom_fields:
                    password_entry['custom_fields'] = custom_fields
            
            passwords.append(password_entry)
        
        return passwords
    except Exception as e:
        logging.error(f"Error importing passwords from JSON: {e}")
        return []


def export_passwords_to_json(passwords: List[Dict], notes: List[Dict] = None, 
                            include_custom_fields: bool = True) -> str:
    """
    Export passwords to a JSON string.
    
    Args:
        passwords: List of password dictionaries with decrypted passwords
        notes: Optional list of secure note dictionaries with decrypted content
        include_custom_fields: Whether to include custom fields
        
    Returns:
        JSON-formatted string
    """
    try:
        export_data = []
        
        # Export passwords
        for password in passwords:
            password_data = {
                'type': 'password',
                'service_name': password.get('service_name', ''),
                'username': password.get('username', ''),
                'password': password.get('password', ''),  # This should be the decrypted password
                'notes': password.get('notes', ''),
                'category': password.get('category_name', '')
            }
            
            # Add custom fields if available and requested
            if include_custom_fields and 'custom_fields' in password:
                custom_fields_dict = {}
                for field in password['custom_fields']:
                    custom_fields_dict[field.get('field_name', '')] = field.get('value', '')
                
                if custom_fields_dict:
                    password_data['custom_fields'] = custom_fields_dict
            
            export_data.append(password_data)
        
        # Export secure notes if provided
        if notes:
            for note in notes:
                note_data = {
                    'type': 'secure_note',
                    'title': note.get('title', ''),
                    'content': note.get('content', ''),  # This should be the decrypted content
                    'category': note.get('category_name', '')
                }
                export_data.append(note_data)
        
        # Convert to JSON string
        return json.dumps(export_data, indent=2)
    except Exception as e:
        logging.error(f"Error exporting passwords to JSON: {e}")
        return "[]"


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
