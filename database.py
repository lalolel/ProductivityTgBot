import asyncio
import asyncpg
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
from config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, DATABASE_URL

class Database:
    """Database connection handler for PostgreSQL using asyncpg."""
    
    def __init__(self):
        self.pool = None
        
    async def create_pool(self):
        """Create connection pool to PostgreSQL."""
        try:
            # Try to connect using DATABASE_URL if available
            if DATABASE_URL:
                self.pool = await asyncpg.create_pool(DATABASE_URL)
            else:
                # Otherwise use individual parameters
                self.pool = await asyncpg.create_pool(
                    host=DB_HOST,
                    port=DB_PORT,
                    database=DB_NAME,
                    user=DB_USER,
                    password=DB_PASSWORD
                )
            
            # Initialize database tables
            await self.init_db()
            logging.info("Database connection established")
        except Exception as e:
            logging.error(f"Database connection error: {e}")
            raise
    
    async def close(self):
        """Close database connection pool."""
        if self.pool:
            await self.pool.close()
            logging.info("Database connection closed")
    
    async def init_db(self):
        """Initialize database tables if they don't exist."""
        async with self.pool.acquire() as conn:
            # Create users table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id BIGINT PRIMARY KEY,
                    username VARCHAR(255),
                    master_password_hash VARCHAR(255) NOT NULL,
                    master_salt VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create categories table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS categories (
                    id SERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    name VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (user_id, name)
                )
            ''')
            
            # Create passwords table with category support
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id SERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
                    service_name VARCHAR(255) NOT NULL,
                    username VARCHAR(255) NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    notes TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (user_id, service_name, username)
                )
            ''')
            
            # Create secure notes table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS secure_notes (
                    id SERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
                    title VARCHAR(255) NOT NULL,
                    encrypted_content TEXT NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (user_id, title)
                )
            ''')
            
            # Create custom fields table for passwords
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS custom_fields (
                    id SERIAL PRIMARY KEY,
                    password_id INTEGER REFERENCES passwords(id) ON DELETE CASCADE,
                    field_name VARCHAR(255) NOT NULL,
                    encrypted_value TEXT NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (password_id, field_name)
                )
            ''')
            
            # Create secure files table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS secure_files (
                    id SERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
                    filename VARCHAR(255) NOT NULL,
                    encrypted_file BYTEA NOT NULL,
                    file_size INTEGER NOT NULL,
                    mime_type VARCHAR(100),
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create shared passwords table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS shared_passwords (
                    id SERIAL PRIMARY KEY,
                    password_id INTEGER NOT NULL REFERENCES passwords(id) ON DELETE CASCADE,
                    shared_by_user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    shared_with_user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    encrypted_password TEXT NOT NULL,
                    expires_at TIMESTAMP WITH TIME ZONE,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (password_id, shared_with_user_id)
                )
            ''')
            
            # Create emergency access table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS emergency_access (
                    id SERIAL PRIMARY KEY,
                    grantor_user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    grantee_user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    wait_time_hours INTEGER NOT NULL DEFAULT 24,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (grantor_user_id, grantee_user_id)
                )
            ''')
            
            # Create emergency access requests table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS emergency_access_requests (
                    id SERIAL PRIMARY KEY,
                    emergency_access_id INTEGER NOT NULL REFERENCES emergency_access(id) ON DELETE CASCADE,
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    approved_at TIMESTAMP WITH TIME ZONE,
                    rejected_at TIMESTAMP WITH TIME ZONE,
                    expires_at TIMESTAMP WITH TIME ZONE
                )
            ''')
            
            # Create audit log table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    action VARCHAR(100) NOT NULL,
                    item_type VARCHAR(50) NOT NULL,
                    item_id INTEGER,
                    details JSONB,
                    ip_address VARCHAR(45),
                    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                )
            ''')
    
    async def get_user(self, user_id: int) -> Optional[Dict]:
        """Get user by Telegram user ID."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow('SELECT * FROM users WHERE user_id = $1', user_id)
            if row:
                return dict(row)
            return None
    
    async def add_user(self, user_id: int, username: str, master_password_hash: str, master_salt: str) -> bool:
        """Add a new user."""
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(
                    'INSERT INTO users (user_id, username, master_password_hash, master_salt) VALUES ($1, $2, $3, $4)',
                    user_id, username, master_password_hash, master_salt
                )
                return True
        except asyncpg.UniqueViolationError:
            # User already exists
            return False
        except Exception as e:
            logging.error(f"Error adding user: {e}")
            return False
    
    async def update_master_password(self, user_id: int, new_password_hash: str, new_salt: str) -> bool:
        """Update user's master password."""
        try:
            async with self.pool.acquire() as conn:
                result = await conn.execute(
                    'UPDATE users SET master_password_hash = $1, master_salt = $2 WHERE user_id = $3',
                    new_password_hash, new_salt, user_id
                )
                return "UPDATE" in result
        except Exception as e:
            logging.error(f"Error updating master password: {e}")
            return False
    
    async def add_password(self, user_id: int, service_name: str, username: str, 
                          encrypted_password: str, notes: str = None) -> Optional[int]:
        """Add a new password entry."""
        try:
            async with self.pool.acquire() as conn:
                return await conn.fetchval(
                    '''
                    INSERT INTO passwords (user_id, service_name, username, encrypted_password, notes)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id
                    ''',
                    user_id, service_name, username, encrypted_password, notes
                )
        except asyncpg.UniqueViolationError:
            # Entry already exists
            return None
        except Exception as e:
            logging.error(f"Error adding password: {e}")
            return None
    
    async def update_password(self, password_id: int, user_id: int, service_name: str = None, 
                             username: str = None, encrypted_password: str = None, notes: str = None) -> bool:
        """Update an existing password entry."""
        try:
            async with self.pool.acquire() as conn:
                # Get current password data
                current = await conn.fetchrow(
                    'SELECT * FROM passwords WHERE id = $1 AND user_id = $2',
                    password_id, user_id
                )
                
                if not current:
                    return False
                
                # Update only provided fields
                result = await conn.execute(
                    '''
                    UPDATE passwords 
                    SET service_name = $1, 
                        username = $2, 
                        encrypted_password = $3, 
                        notes = $4,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $5 AND user_id = $6
                    ''',
                    service_name or current['service_name'],
                    username or current['username'],
                    encrypted_password or current['encrypted_password'],
                    notes if notes is not None else current['notes'],
                    password_id, user_id
                )
                return "UPDATE" in result
        except Exception as e:
            logging.error(f"Error updating password: {e}")
            return False
    
    async def delete_password(self, password_id: int, user_id: int) -> bool:
        """Delete password entry."""
        try:
            async with self.pool.acquire() as conn:
                result = await conn.execute(
                    'DELETE FROM passwords WHERE id = $1 AND user_id = $2',
                    password_id, user_id
                )
                return "DELETE" in result
        except Exception as e:
            logging.error(f"Error deleting password: {e}")
            return False
    
    async def get_password(self, password_id: int, user_id: int) -> Optional[Dict]:
        """Get a specific password entry."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                'SELECT * FROM passwords WHERE id = $1 AND user_id = $2',
                password_id, user_id
            )
            if row:
                return dict(row)
            return None
    
    async def get_all_passwords(self, user_id: int) -> List[Dict]:
        """Get all password entries for a user."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                'SELECT * FROM passwords WHERE user_id = $1 ORDER BY service_name',
                user_id
            )
            return [dict(row) for row in rows]
    
    async def search_passwords(self, user_id: int, search_term: str) -> List[Dict]:
        """Search for password entries by service name or username."""
        search_pattern = f"%{search_term}%"
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                '''
                SELECT p.*, c.name as category_name 
                FROM passwords p
                LEFT JOIN categories c ON p.category_id = c.id
                WHERE p.user_id = $1 AND (p.service_name ILIKE $2 OR p.username ILIKE $2)
                ORDER BY p.service_name
                ''',
                user_id, search_pattern
            )
            return [dict(row) for row in rows]
    
    # Category management
    async def get_categories(self, user_id: int) -> List[Dict]:
        """Get all categories for a user."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                'SELECT * FROM categories WHERE user_id = $1 ORDER BY name',
                user_id
            )
            return [dict(row) for row in rows]
    
    async def get_category(self, category_id: int, user_id: int) -> Optional[Dict]:
        """Get a specific category."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                'SELECT * FROM categories WHERE id = $1 AND user_id = $2',
                category_id, user_id
            )
            if row:
                return dict(row)
            return None
    
    async def add_category(self, user_id: int, name: str) -> Optional[int]:
        """Add a new category."""
        try:
            async with self.pool.acquire() as conn:
                return await conn.fetchval(
                    'INSERT INTO categories (user_id, name) VALUES ($1, $2) RETURNING id',
                    user_id, name
                )
        except asyncpg.UniqueViolationError:
            # Category already exists
            return None
        except Exception as e:
            logging.error(f"Error adding category: {e}")
            return None
    
    async def update_category(self, category_id: int, user_id: int, name: str) -> bool:
        """Update a category name."""
        try:
            async with self.pool.acquire() as conn:
                result = await conn.execute(
                    'UPDATE categories SET name = $1 WHERE id = $2 AND user_id = $3',
                    name, category_id, user_id
                )
                return "UPDATE" in result
        except asyncpg.UniqueViolationError:
            # Name already exists
            return False
        except Exception as e:
            logging.error(f"Error updating category: {e}")
            return False
    
    async def delete_category(self, category_id: int, user_id: int) -> bool:
        """Delete a category."""
        try:
            async with self.pool.acquire() as conn:
                # First update all passwords in this category to have NULL category_id
                await conn.execute(
                    'UPDATE passwords SET category_id = NULL WHERE category_id = $1 AND user_id = $2',
                    category_id, user_id
                )
                
                # Then delete the category
                result = await conn.execute(
                    'DELETE FROM categories WHERE id = $1 AND user_id = $2',
                    category_id, user_id
                )
                return "DELETE" in result
        except Exception as e:
            logging.error(f"Error deleting category: {e}")
            return False
    
    async def update_password_category(self, password_id: int, user_id: int, category_id: int = None) -> bool:
        """Move a password to a different category."""
        try:
            async with self.pool.acquire() as conn:
                result = await conn.execute(
                    'UPDATE passwords SET category_id = $1 WHERE id = $2 AND user_id = $3',
                    category_id, password_id, user_id
                )
                return "UPDATE" in result
        except Exception as e:
            logging.error(f"Error updating password category: {e}")
            return False
            
    async def get_passwords_by_category(self, user_id: int, category_id: int = None) -> List[Dict]:
        """Get all passwords in a specific category."""
        async with self.pool.acquire() as conn:
            if category_id is None:
                # Get passwords with no category
                rows = await conn.fetch(
                    'SELECT * FROM passwords WHERE user_id = $1 AND category_id IS NULL ORDER BY service_name',
                    user_id
                )
            else:
                # Get passwords in the specified category
                rows = await conn.fetch(
                    'SELECT * FROM passwords WHERE user_id = $1 AND category_id = $2 ORDER BY service_name',
                    user_id, category_id
                )
            return [dict(row) for row in rows]

# Secure Notes Functions
    async def add_secure_note(self, user_id: int, title: str, encrypted_content: str, 
                              category_id: int = None) -> Optional[int]:
        """Add a new secure note."""
        try:
            async with self.pool.acquire() as conn:
                return await conn.fetchval(
                    '''
                    INSERT INTO secure_notes (user_id, category_id, title, encrypted_content)
                    VALUES ($1, $2, $3, $4)
                    RETURNING id
                    ''',
                    user_id, category_id, title, encrypted_content
                )
        except asyncpg.UniqueViolationError:
            # Note with this title already exists
            return None
        except Exception as e:
            logging.error(f"Error adding secure note: {e}")
            return None
    
    async def get_secure_note(self, note_id: int, user_id: int) -> Optional[Dict]:
        """Get a specific secure note."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                '''
                SELECT n.*, c.name as category_name
                FROM secure_notes n
                LEFT JOIN categories c ON n.category_id = c.id
                WHERE n.id = $1 AND n.user_id = $2
                ''',
                note_id, user_id
            )
            if row:
                return dict(row)
            return None
    
    async def get_all_secure_notes(self, user_id: int) -> List[Dict]:
        """Get all secure notes for a user."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                '''
                SELECT n.*, c.name as category_name
                FROM secure_notes n
                LEFT JOIN categories c ON n.category_id = c.id
                WHERE n.user_id = $1
                ORDER BY n.title
                ''',
                user_id
            )
            return [dict(row) for row in rows]
    
    async def get_secure_notes_by_category(self, user_id: int, category_id: int = None) -> List[Dict]:
        """Get all secure notes in a specific category."""
        async with self.pool.acquire() as conn:
            if category_id is None:
                # Get notes with no category
                rows = await conn.fetch(
                    '''
                    SELECT n.*, c.name as category_name
                    FROM secure_notes n
                    LEFT JOIN categories c ON n.category_id = c.id
                    WHERE n.user_id = $1 AND n.category_id IS NULL
                    ORDER BY n.title
                    ''',
                    user_id
                )
            else:
                # Get notes in the specified category
                rows = await conn.fetch(
                    '''
                    SELECT n.*, c.name as category_name
                    FROM secure_notes n
                    LEFT JOIN categories c ON n.category_id = c.id
                    WHERE n.user_id = $1 AND n.category_id = $2
                    ORDER BY n.title
                    ''',
                    user_id, category_id
                )
            return [dict(row) for row in rows]
    
    async def update_secure_note(self, note_id: int, user_id: int, 
                                title: str = None, encrypted_content: str = None,
                                category_id: int = None) -> bool:
        """Update an existing secure note."""
        try:
            async with self.pool.acquire() as conn:
                # Get current note data
                current = await conn.fetchrow(
                    'SELECT * FROM secure_notes WHERE id = $1 AND user_id = $2',
                    note_id, user_id
                )
                
                if not current:
                    return False
                
                # Update only provided fields
                result = await conn.execute(
                    '''
                    UPDATE secure_notes 
                    SET title = $1, 
                        encrypted_content = $2, 
                        category_id = $3,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $4 AND user_id = $5
                    ''',
                    title or current['title'],
                    encrypted_content or current['encrypted_content'],
                    category_id if category_id is not None else current['category_id'],
                    note_id, user_id
                )
                return "UPDATE" in result
        except Exception as e:
            logging.error(f"Error updating secure note: {e}")
            return False
    
    async def delete_secure_note(self, note_id: int, user_id: int) -> bool:
        """Delete secure note."""
        try:
            async with self.pool.acquire() as conn:
                result = await conn.execute(
                    'DELETE FROM secure_notes WHERE id = $1 AND user_id = $2',
                    note_id, user_id
                )
                return "DELETE" in result
        except Exception as e:
            logging.error(f"Error deleting secure note: {e}")
            return False
    
    # Custom Fields Functions
    async def add_custom_field(self, password_id: int, field_name: str, 
                              encrypted_value: str) -> Optional[int]:
        """Add a custom field to a password entry."""
        try:
            async with self.pool.acquire() as conn:
                return await conn.fetchval(
                    '''
                    INSERT INTO custom_fields (password_id, field_name, encrypted_value)
                    VALUES ($1, $2, $3)
                    RETURNING id
                    ''',
                    password_id, field_name, encrypted_value
                )
        except asyncpg.UniqueViolationError:
            # Field already exists for this password
            return None
        except Exception as e:
            logging.error(f"Error adding custom field: {e}")
            return None
    
    async def get_custom_fields(self, password_id: int) -> List[Dict]:
        """Get all custom fields for a password."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                'SELECT * FROM custom_fields WHERE password_id = $1 ORDER BY field_name',
                password_id
            )
            return [dict(row) for row in rows]
    
    async def update_custom_field(self, field_id: int, encrypted_value: str) -> bool:
        """Update a custom field value."""
        try:
            async with self.pool.acquire() as conn:
                result = await conn.execute(
                    '''
                    UPDATE custom_fields 
                    SET encrypted_value = $1,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $2
                    ''',
                    encrypted_value, field_id
                )
                return "UPDATE" in result
        except Exception as e:
            logging.error(f"Error updating custom field: {e}")
            return False
    
    async def delete_custom_field(self, field_id: int) -> bool:
        """Delete a custom field."""
        try:
            async with self.pool.acquire() as conn:
                result = await conn.execute(
                    'DELETE FROM custom_fields WHERE id = $1',
                    field_id
                )
                return "DELETE" in result
        except Exception as e:
            logging.error(f"Error deleting custom field: {e}")
            return False
    
    # Password Sharing Functions
    async def share_password(self, password_id: int, shared_by_user_id: int, 
                            shared_with_user_id: int, encrypted_password: str,
                            expires_at: datetime = None) -> Optional[int]:
        """Share a password with another user."""
        try:
            async with self.pool.acquire() as conn:
                return await conn.fetchval(
                    '''
                    INSERT INTO shared_passwords 
                    (password_id, shared_by_user_id, shared_with_user_id, encrypted_password, expires_at)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id
                    ''',
                    password_id, shared_by_user_id, shared_with_user_id, encrypted_password, expires_at
                )
        except asyncpg.UniqueViolationError:
            # Already shared with this user
            return None
        except Exception as e:
            logging.error(f"Error sharing password: {e}")
            return None
    
    async def get_shared_passwords(self, user_id: int) -> List[Dict]:
        """Get passwords shared with a user."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                '''
                SELECT sp.*, p.service_name, p.username, u.username as shared_by_username
                FROM shared_passwords sp
                JOIN passwords p ON sp.password_id = p.id
                JOIN users u ON sp.shared_by_user_id = u.user_id
                WHERE sp.shared_with_user_id = $1 
                AND (sp.expires_at IS NULL OR sp.expires_at > CURRENT_TIMESTAMP)
                ORDER BY p.service_name
                ''',
                user_id
            )
            return [dict(row) for row in rows]
    
    async def get_passwords_shared_by_user(self, user_id: int) -> List[Dict]:
        """Get passwords shared by a user."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                '''
                SELECT sp.*, p.service_name, p.username, u.username as shared_with_username
                FROM shared_passwords sp
                JOIN passwords p ON sp.password_id = p.id
                JOIN users u ON sp.shared_with_user_id = u.user_id
                WHERE sp.shared_by_user_id = $1
                ORDER BY p.service_name
                ''',
                user_id
            )
            return [dict(row) for row in rows]
    
    async def delete_shared_password(self, shared_id: int, user_id: int) -> bool:
        """Delete a shared password (by either the sharer or receiver)."""
        try:
            async with self.pool.acquire() as conn:
                result = await conn.execute(
                    '''
                    DELETE FROM shared_passwords 
                    WHERE id = $1 AND (shared_by_user_id = $2 OR shared_with_user_id = $2)
                    ''',
                    shared_id, user_id
                )
                return "DELETE" in result
        except Exception as e:
            logging.error(f"Error deleting shared password: {e}")
            return False
            
    # Audit Log Functions
    async def add_audit_log(self, user_id: int, action: str, item_type: str,
                           item_id: int = None, details: Dict = None,
                           ip_address: str = None) -> Optional[int]:
        """Add an audit log entry."""
        try:
            async with self.pool.acquire() as conn:
                return await conn.fetchval(
                    '''
                    INSERT INTO audit_logs 
                    (user_id, action, item_type, item_id, details, ip_address)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    RETURNING id
                    ''',
                    user_id, action, item_type, item_id, 
                    details if isinstance(details, str) else json.dumps(details or {}),
                    ip_address
                )
        except Exception as e:
            logging.error(f"Error adding audit log: {e}")
            return None
    
    async def get_user_audit_logs(self, user_id: int, limit: int = 100) -> List[Dict]:
        """Get audit logs for a user."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                '''
                SELECT * FROM audit_logs
                WHERE user_id = $1
                ORDER BY timestamp DESC
                LIMIT $2
                ''',
                user_id, limit
            )
            return [dict(row) for row in rows]

# Database instance
db = Database()
