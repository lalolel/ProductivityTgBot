import asyncio
import asyncpg
import logging
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
            
            # Create passwords table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id SERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    service_name VARCHAR(255) NOT NULL,
                    username VARCHAR(255) NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    notes TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (user_id, service_name, username)
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
                SELECT * FROM passwords 
                WHERE user_id = $1 AND (service_name ILIKE $2 OR username ILIKE $2)
                ORDER BY service_name
                ''',
                user_id, search_pattern
            )
            return [dict(row) for row in rows]

# Database instance
db = Database()
