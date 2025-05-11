import os
import base64
import hashlib
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Tuple, Optional

class PasswordEncryption:
    """Class for handling password encryption and decryption."""
    
    @staticmethod
    def generate_salt() -> str:
        """Generate a random salt."""
        return base64.b64encode(os.urandom(32)).decode('utf-8')
    
    @staticmethod
    def hash_master_password(password: str, salt: str) -> str:
        """Hash the master password using PBKDF2."""
        try:
            # Convert salt from base64 to bytes
            salt_bytes = base64.b64decode(salt)
            
            # Hash the password with the salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_bytes,
                iterations=100000,
            )
            
            key = base64.b64encode(kdf.derive(password.encode())).decode('utf-8')
            return key
        except Exception as e:
            logging.error(f"Error hashing master password: {e}")
            raise
    
    @staticmethod
    def verify_master_password(password: str, stored_hash: str, salt: str) -> bool:
        """Verify if the provided master password matches the stored hash."""
        try:
            calculated_hash = PasswordEncryption.hash_master_password(password, salt)
            return calculated_hash == stored_hash
        except Exception as e:
            logging.error(f"Error verifying master password: {e}")
            return False
    
    @staticmethod
    def derive_encryption_key(master_password: str, salt: str) -> bytes:
        """Derive an encryption key from the master password and salt."""
        try:
            # Convert salt from base64 to bytes
            salt_bytes = base64.b64decode(salt)
            
            # Create a key derivation function
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_bytes,
                iterations=100000,
            )
            
            # Derive the key
            key = kdf.derive(master_password.encode())
            return base64.urlsafe_b64encode(key)
        except Exception as e:
            logging.error(f"Error deriving encryption key: {e}")
            raise
    
    @staticmethod
    def encrypt_password(password: str, master_password: str, salt: str) -> Optional[str]:
        """Encrypt a password using the master password."""
        try:
            # Derive the encryption key
            key = PasswordEncryption.derive_encryption_key(master_password, salt)
            
            # Create a Fernet cipher object
            cipher = Fernet(key)
            
            # Encrypt the password
            encrypted_password = cipher.encrypt(password.encode())
            
            # Return the encrypted password as a base64-encoded string
            return base64.b64encode(encrypted_password).decode('utf-8')
        except Exception as e:
            logging.error(f"Error encrypting password: {e}")
            return None
    
    @staticmethod
    def decrypt_password(encrypted_password: str, master_password: str, salt: str) -> Optional[str]:
        """Decrypt a password using the master password."""
        try:
            # Derive the encryption key
            key = PasswordEncryption.derive_encryption_key(master_password, salt)
            
            # Create a Fernet cipher object
            cipher = Fernet(key)
            
            # Decode the encrypted password from base64
            encrypted_bytes = base64.b64decode(encrypted_password)
            
            # Decrypt the password
            decrypted_password = cipher.decrypt(encrypted_bytes).decode('utf-8')
            
            return decrypted_password
        except Exception as e:
            logging.error(f"Error decrypting password: {e}")
            return None
    
    @staticmethod
    def setup_user_encryption(master_password: str) -> Tuple[str, str]:
        """Set up encryption for a new user."""
        # Generate a salt
        salt = PasswordEncryption.generate_salt()
        
        # Hash the master password
        hashed_password = PasswordEncryption.hash_master_password(master_password, salt)
        
        return hashed_password, salt
