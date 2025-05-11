from typing import Dict, List, Optional, Any
from datetime import datetime
import json

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


class Category:
    """Model representing a category for organizing items."""
    
    def __init__(self, id: int = None, user_id: int = None, 
                 name: str = None, created_at: datetime = None):
        self.id = id
        self.user_id = user_id
        self.name = name
        self.created_at = created_at or datetime.now()
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Category':
        """Create a Category instance from a dictionary."""
        return cls(
            id=data.get('id'),
            user_id=data.get('user_id'),
            name=data.get('name'),
            created_at=data.get('created_at')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert Category instance to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'created_at': self.created_at
        }
    
    def __str__(self) -> str:
        """String representation of category."""
        return f"Category(id={self.id}, name={self.name})"


class Password:
    """Model representing a stored password entry."""
    
    def __init__(self, id: int = None, user_id: int = None, category_id: int = None,
                 service_name: str = None, username: str = None,
                 encrypted_password: str = None, notes: str = None,
                 created_at: datetime = None, updated_at: datetime = None,
                 custom_fields: List['CustomField'] = None):
        self.id = id
        self.user_id = user_id
        self.category_id = category_id
        self.service_name = service_name
        self.username = username
        self.encrypted_password = encrypted_password
        self.notes = notes
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or self.created_at
        self.custom_fields = custom_fields or []
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Password':
        """Create a Password instance from a dictionary."""
        return cls(
            id=data.get('id'),
            user_id=data.get('user_id'),
            category_id=data.get('category_id'),
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
            'category_id': self.category_id,
            'service_name': self.service_name,
            'username': self.username,
            'encrypted_password': self.encrypted_password,
            'notes': self.notes,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'custom_fields': [field.to_dict() for field in self.custom_fields] if self.custom_fields else []
        }
    
    def __str__(self) -> str:
        """String representation of password entry."""
        return f"Password(id={self.id}, service={self.service_name}, username={self.username})"


class CustomField:
    """Model representing a custom field for a password entry."""
    
    def __init__(self, id: int = None, password_id: int = None,
                 field_name: str = None, encrypted_value: str = None,
                 created_at: datetime = None, updated_at: datetime = None):
        self.id = id
        self.password_id = password_id
        self.field_name = field_name
        self.encrypted_value = encrypted_value
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or self.created_at
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CustomField':
        """Create a CustomField instance from a dictionary."""
        return cls(
            id=data.get('id'),
            password_id=data.get('password_id'),
            field_name=data.get('field_name'),
            encrypted_value=data.get('encrypted_value'),
            created_at=data.get('created_at'),
            updated_at=data.get('updated_at')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert CustomField instance to dictionary."""
        return {
            'id': self.id,
            'password_id': self.password_id,
            'field_name': self.field_name,
            'encrypted_value': self.encrypted_value,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }


class SecureNote:
    """Model representing a secure note entry."""
    
    def __init__(self, id: int = None, user_id: int = None, category_id: int = None,
                 title: str = None, encrypted_content: str = None,
                 created_at: datetime = None, updated_at: datetime = None):
        self.id = id
        self.user_id = user_id
        self.category_id = category_id
        self.title = title
        self.encrypted_content = encrypted_content
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or self.created_at
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecureNote':
        """Create a SecureNote instance from a dictionary."""
        return cls(
            id=data.get('id'),
            user_id=data.get('user_id'),
            category_id=data.get('category_id'),
            title=data.get('title'),
            encrypted_content=data.get('encrypted_content'),
            created_at=data.get('created_at'),
            updated_at=data.get('updated_at')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert SecureNote instance to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'category_id': self.category_id,
            'title': self.title,
            'encrypted_content': self.encrypted_content,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }
    
    def __str__(self) -> str:
        """String representation of secure note."""
        return f"SecureNote(id={self.id}, title={self.title})"


class SecureFile:
    """Model representing a securely stored file."""
    
    def __init__(self, id: int = None, user_id: int = None, category_id: int = None,
                 filename: str = None, encrypted_file: bytes = None, 
                 file_size: int = None, mime_type: str = None,
                 created_at: datetime = None, updated_at: datetime = None):
        self.id = id
        self.user_id = user_id
        self.category_id = category_id
        self.filename = filename
        self.encrypted_file = encrypted_file
        self.file_size = file_size
        self.mime_type = mime_type
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or self.created_at
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecureFile':
        """Create a SecureFile instance from a dictionary."""
        return cls(
            id=data.get('id'),
            user_id=data.get('user_id'),
            category_id=data.get('category_id'),
            filename=data.get('filename'),
            encrypted_file=data.get('encrypted_file'),
            file_size=data.get('file_size'),
            mime_type=data.get('mime_type'),
            created_at=data.get('created_at'),
            updated_at=data.get('updated_at')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert SecureFile instance to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'category_id': self.category_id,
            'filename': self.filename,
            'file_size': self.file_size,
            'mime_type': self.mime_type,
            'created_at': self.created_at,
            'updated_at': self.updated_at
            # Note: encrypted_file is not included as it can be large binary data
        }
    
    def __str__(self) -> str:
        """String representation of secure file."""
        return f"SecureFile(id={self.id}, filename={self.filename}, size={self.file_size})"


class SharedPassword:
    """Model representing a password shared with another user."""
    
    def __init__(self, id: int = None, password_id: int = None,
                 shared_by_user_id: int = None, shared_with_user_id: int = None,
                 encrypted_password: str = None, expires_at: datetime = None,
                 created_at: datetime = None):
        self.id = id
        self.password_id = password_id
        self.shared_by_user_id = shared_by_user_id
        self.shared_with_user_id = shared_with_user_id
        self.encrypted_password = encrypted_password
        self.expires_at = expires_at
        self.created_at = created_at or datetime.now()
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SharedPassword':
        """Create a SharedPassword instance from a dictionary."""
        return cls(
            id=data.get('id'),
            password_id=data.get('password_id'),
            shared_by_user_id=data.get('shared_by_user_id'),
            shared_with_user_id=data.get('shared_with_user_id'),
            encrypted_password=data.get('encrypted_password'),
            expires_at=data.get('expires_at'),
            created_at=data.get('created_at')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert SharedPassword instance to dictionary."""
        return {
            'id': self.id,
            'password_id': self.password_id,
            'shared_by_user_id': self.shared_by_user_id,
            'shared_with_user_id': self.shared_with_user_id,
            'encrypted_password': self.encrypted_password,
            'expires_at': self.expires_at,
            'created_at': self.created_at
        }


class EmergencyAccess:
    """Model representing emergency access granted to another user."""
    
    def __init__(self, id: int = None, grantor_user_id: int = None,
                 grantee_user_id: int = None, wait_time_hours: int = 24,
                 created_at: datetime = None):
        self.id = id
        self.grantor_user_id = grantor_user_id
        self.grantee_user_id = grantee_user_id
        self.wait_time_hours = wait_time_hours
        self.created_at = created_at or datetime.now()
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EmergencyAccess':
        """Create an EmergencyAccess instance from a dictionary."""
        return cls(
            id=data.get('id'),
            grantor_user_id=data.get('grantor_user_id'),
            grantee_user_id=data.get('grantee_user_id'),
            wait_time_hours=data.get('wait_time_hours', 24),
            created_at=data.get('created_at')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert EmergencyAccess instance to dictionary."""
        return {
            'id': self.id,
            'grantor_user_id': self.grantor_user_id,
            'grantee_user_id': self.grantee_user_id,
            'wait_time_hours': self.wait_time_hours,
            'created_at': self.created_at
        }


class EmergencyAccessRequest:
    """Model representing a request for emergency access."""
    
    def __init__(self, id: int = None, emergency_access_id: int = None,
                 status: str = 'pending', requested_at: datetime = None,
                 approved_at: datetime = None, rejected_at: datetime = None,
                 expires_at: datetime = None):
        self.id = id
        self.emergency_access_id = emergency_access_id
        self.status = status
        self.requested_at = requested_at or datetime.now()
        self.approved_at = approved_at
        self.rejected_at = rejected_at
        self.expires_at = expires_at
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EmergencyAccessRequest':
        """Create an EmergencyAccessRequest instance from a dictionary."""
        return cls(
            id=data.get('id'),
            emergency_access_id=data.get('emergency_access_id'),
            status=data.get('status', 'pending'),
            requested_at=data.get('requested_at'),
            approved_at=data.get('approved_at'),
            rejected_at=data.get('rejected_at'),
            expires_at=data.get('expires_at')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert EmergencyAccessRequest instance to dictionary."""
        return {
            'id': self.id,
            'emergency_access_id': self.emergency_access_id,
            'status': self.status,
            'requested_at': self.requested_at,
            'approved_at': self.approved_at,
            'rejected_at': self.rejected_at,
            'expires_at': self.expires_at
        }


class AuditLog:
    """Model representing an audit log entry."""
    
    def __init__(self, id: int = None, user_id: int = None,
                 action: str = None, item_type: str = None,
                 item_id: int = None, details: Dict = None,
                 ip_address: str = None, timestamp: datetime = None):
        self.id = id
        self.user_id = user_id
        self.action = action
        self.item_type = item_type
        self.item_id = item_id
        self.details = details or {}
        self.ip_address = ip_address
        self.timestamp = timestamp or datetime.now()
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditLog':
        """Create an AuditLog instance from a dictionary."""
        details = data.get('details')
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except:
                details = {}
        
        return cls(
            id=data.get('id'),
            user_id=data.get('user_id'),
            action=data.get('action'),
            item_type=data.get('item_type'),
            item_id=data.get('item_id'),
            details=details,
            ip_address=data.get('ip_address'),
            timestamp=data.get('timestamp')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert AuditLog instance to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'item_type': self.item_type,
            'item_id': self.item_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp
        }


class UserSession:
    """Model for storing user session data."""
    
    def __init__(self, user_id: int, authenticated: bool = False, 
                 master_password: str = None, state: str = None,
                 temp_data: Dict[str, Any] = None, expires_at: datetime = None,
                 last_activity: datetime = None, current_category_id: int = None):
        self.user_id = user_id
        self.authenticated = authenticated
        self.master_password = master_password  # Only stored in memory, never persisted
        self.state = state  # Track user's current operation state
        self.temp_data = temp_data or {}  # Temporary data storage for multi-step operations
        self.expires_at = expires_at
        self.last_activity = last_activity or datetime.now()
        self.current_category_id = current_category_id  # Used for category navigation
        self.import_mode = False  # Flag for password import process
        self.export_mode = False  # Flag for password export process
        
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return self.authenticated and self.master_password is not None
    
    def authenticate(self, master_password: str) -> None:
        """Authenticate user with master password."""
        self.authenticated = True
        self.master_password = master_password
        self.last_activity = datetime.now()
    
    def logout(self) -> None:
        """Log out user."""
        self.authenticated = False
        self.master_password = None
        self.state = None
        self.temp_data = {}
        self.current_category_id = None
        self.import_mode = False
        self.export_mode = False
    
    def update_state(self, state: str) -> None:
        """Update user state."""
        self.state = state
        self.last_activity = datetime.now()
    
    def set_temp_data(self, key: str, value: Any) -> None:
        """Set temporary data."""
        self.temp_data[key] = value
    
    def get_temp_data(self, key: str, default: Any = None) -> Any:
        """Get temporary data."""
        return self.temp_data.get(key, default)
    
    def clear_temp_data(self) -> None:
        """Clear temporary data."""
        self.temp_data = {}
    
    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now()
    
    def set_category(self, category_id: int) -> None:
        """Set the current category."""
        self.current_category_id = category_id
        self.update_activity()
    
    def clear_category(self) -> None:
        """Clear the current category."""
        self.current_category_id = None
    
    def start_import(self) -> None:
        """Start password import process."""
        self.import_mode = True
        self.update_activity()
    
    def end_import(self) -> None:
        """End password import process."""
        self.import_mode = False
        self.update_activity()
    
    def start_export(self) -> None:
        """Start password export process."""
        self.export_mode = True
        self.update_activity()
    
    def end_export(self) -> None:
        """End password export process."""
        self.export_mode = False
        self.update_activity()
    
    def is_session_expired(self, timeout_minutes: int = 30) -> bool:
        """Check if session has expired due to inactivity."""
        if not self.last_activity:
            return False
        
        elapsed = datetime.now() - self.last_activity
        return elapsed.total_seconds() > (timeout_minutes * 60)
