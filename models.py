from typing import Dict, List, Optional, Any
from datetime import datetime

class User:
    """Model representing a user in the system."""
    
    def __init__(self, user_id: int, username: str = None, 
                 master_password_hash: str = None, master_salt: str = None,
                 created_at: datetime = None):
        self.user_id = user_id
        self.username = username
        self.master_password_hash = master_password_hash
        self.master_salt = master_salt
        self.created_at = created_at or datetime.now()
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create a User instance from a dictionary."""
        return cls(
            user_id=data['user_id'],
            username=data.get('username'),
            master_password_hash=data.get('master_password_hash'),
            master_salt=data.get('master_salt'),
            created_at=data.get('created_at')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert User instance to dictionary."""
        return {
            'user_id': self.user_id,
            'username': self.username,
            'master_password_hash': self.master_password_hash,
            'master_salt': self.master_salt,
            'created_at': self.created_at
        }
    
    def is_registered(self) -> bool:
        """Check if user has completed registration."""
        return self.master_password_hash is not None and self.master_salt is not None


class Password:
    """Model representing a stored password entry."""
    
    def __init__(self, id: int = None, user_id: int = None, 
                 service_name: str = None, username: str = None,
                 encrypted_password: str = None, notes: str = None,
                 created_at: datetime = None, updated_at: datetime = None):
        self.id = id
        self.user_id = user_id
        self.service_name = service_name
        self.username = username
        self.encrypted_password = encrypted_password
        self.notes = notes
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or self.created_at
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Password':
        """Create a Password instance from a dictionary."""
        return cls(
            id=data.get('id'),
            user_id=data.get('user_id'),
            service_name=data.get('service_name'),
            username=data.get('username'),
            encrypted_password=data.get('encrypted_password'),
            notes=data.get('notes'),
            created_at=data.get('created_at'),
            updated_at=data.get('updated_at')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert Password instance to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'service_name': self.service_name,
            'username': self.username,
            'encrypted_password': self.encrypted_password,
            'notes': self.notes,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }
    
    def __str__(self) -> str:
        """String representation of password entry."""
        return f"Password(id={self.id}, service={self.service_name}, username={self.username})"


class UserSession:
    """Model for storing user session data."""
    
    def __init__(self, user_id: int, authenticated: bool = False, 
                 master_password: str = None, state: str = None,
                 temp_data: Dict[str, Any] = None, expires_at: datetime = None):
        self.user_id = user_id
        self.authenticated = authenticated
        self.master_password = master_password  # Only stored in memory, never persisted
        self.state = state  # Track user's current operation state
        self.temp_data = temp_data or {}  # Temporary data storage for multi-step operations
        self.expires_at = expires_at
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return self.authenticated and self.master_password is not None
    
    def authenticate(self, master_password: str) -> None:
        """Authenticate user with master password."""
        self.authenticated = True
        self.master_password = master_password
    
    def logout(self) -> None:
        """Log out user."""
        self.authenticated = False
        self.master_password = None
        self.state = None
        self.temp_data = {}
    
    def update_state(self, state: str) -> None:
        """Update user state."""
        self.state = state
    
    def set_temp_data(self, key: str, value: Any) -> None:
        """Set temporary data."""
        self.temp_data[key] = value
    
    def get_temp_data(self, key: str, default: Any = None) -> Any:
        """Get temporary data."""
        return self.temp_data.get(key, default)
    
    def clear_temp_data(self) -> None:
        """Clear temporary data."""
        self.temp_data = {}
