import socket
import threading
import os
import hashlib
import pymysql as mysql
import json
from datetime import datetime

# --- Configuration ---
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5001
DATABASE_CONFIG = {
    'host': 'localhost',
    'user': 'sfts_user',
    'password': 'Wzy020618',
    'database': 'secure_file_transfer'
}
BUFFER_SIZE = 65536
ENCODING = 'utf-8'


def log_activity(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")


# --- Database Interaction ---
def create_db_connection():
    """Creates and returns a MySQL database connection."""
    try:
        mydb = mysql.connect(
            host=DATABASE_CONFIG['host'],
            user=DATABASE_CONFIG['user'],
            password=DATABASE_CONFIG['password'],
            database=DATABASE_CONFIG['database']
        )
        log_activity("Database connection established.")
        return mydb
    except Exception as err:
        log_activity(f"Error connecting to MySQL: {err}")
        return None


def create_tables():
    """Creates necessary database tables if they don't exist."""
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        try:
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    public_key TEXT NOT NULL,
                    role VARCHAR(20) NOT NULL DEFAULT 'regular'
                )
            """)
            
            # Create permissions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS permissions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(50) UNIQUE NOT NULL
                )
            """)
            
            # Insert default permissions if table is empty
            cursor.execute("SELECT COUNT(*) FROM permissions")
            if cursor.fetchone()[0] == 0:
                cursor.execute("""
                    INSERT INTO permissions (name) VALUES 
                    ('read'), ('write'), ('manage_users'), ('manage_files')
                """)
            
            # Create user_permissions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_permissions (
                    user_id INT NOT NULL,
                    permission_id INT NOT NULL,
                    PRIMARY KEY (user_id, permission_id),
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (permission_id) REFERENCES permissions(id)
                )
            """)
            
            # Create file_transfers table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_transfers (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    sender_id INT NOT NULL,
                    recipient_id INT NOT NULL,
                    filename VARCHAR(255) NOT NULL,
                    file_size INT NOT NULL,
                    transfer_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(20) NOT NULL,
                    encrypted_key TEXT NOT NULL,
                    original_hash TEXT,
                    FOREIGN KEY (sender_id) REFERENCES users(id),
                    FOREIGN KEY (recipient_id) REFERENCES users(id)
                )
            """)
            
            # Create file_permissions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_permissions (
                    file_id INT NOT NULL,
                    user_id INT,
                    permission_type VARCHAR(20) NOT NULL,
                    is_public BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (file_id) REFERENCES file_transfers(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            mydb.commit()
            log_activity("Database tables verified and created if needed")
        except Exception as err:
            log_activity(f"Error creating database tables: {err}")
        finally:
            cursor.close()
            mydb.close()


def check_username_exists(username):
    """Check if a username already exists in the database.
    
    Args:
        username (str): The username to check
        
    Returns:
        bool: True if username exists, False otherwise
    """
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        try:
            # Use row lock when checking usernames
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s FOR UPDATE", (username,))
            count = cursor.fetchone()[0]
            cursor.close()
            mydb.close()
            return count > 0
        except Exception as err:
            log_activity(f"Error checking username existence: {err}")
            cursor.close()
            mydb.close()
            return False
    return False


def register_user(username, password, client_public_key, requested_role=None, requester_id=None):
    """Registers a new user in the database.
    
    Args:
        username (str): The username to register
        password (str): The password to hash and store
        client_public_key (str): The client's public key in PEM format
        requested_role (str, optional): The requested role ('admin' or 'regular')
        requester_id (int, optional): The ID of the user making the request
        
    Returns:
        bool: True if registration successful, False otherwise
    """
    mydb = create_db_connection()
    if not mydb:
        log_activity(f"Registration failed: Database connection error")
        return False
        
    cursor = mydb.cursor()
    try:
        # Start transaction
        mydb.begin()
        
        # Check if username exists with a row lock
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s FOR UPDATE", (username,))
        if cursor.fetchone()[0] > 0:
            log_activity(f"Registration failed: Username '{username}' already exists.")
            mydb.rollback()
            cursor.close()
            mydb.close()
            return False  # Username already exists
    
        # Check if this is the first user
        cursor.execute("SELECT COUNT(*) FROM users")
        is_first_user = cursor.fetchone()[0] == 0
        
        # Default role is regular
        role = 'regular'
        
        # If admin role requested, validate requester has permission
        if requested_role == 'admin':
            # First user can be admin
            if is_first_user:
                role = 'admin'
            # Otherwise, check if requester is an admin
            elif requester_id:
                cursor.execute("SELECT role FROM users WHERE id = %s", (requester_id,))
                requester_role = cursor.fetchone()
                if requester_role and requester_role[0] == 'admin':
                    role = 'admin'
                else:
                    log_activity(f"Attempt to create admin user '{username}' by non-admin user ID {requester_id}")
                    mydb.rollback()
                    cursor.close()
                    mydb.close()
                    return False
            else:
                log_activity(f"Unauthorized attempt to create admin user '{username}'")
                mydb.rollback()
                cursor.close()
                mydb.close() 
                return False
        # First user is always admin regardless of requested role
        elif is_first_user:
            role = 'admin'
            
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        cursor.execute("INSERT INTO users (username, password, public_key, role) VALUES (%s, %s, %s, %s)",
                      (username, hashed_password, client_public_key, role))
        user_id = cursor.lastrowid
        
        # If role is admin, give all permissions
        if role == 'admin':
            # Get all permission IDs
            cursor.execute("SELECT id FROM permissions")
            permissions = cursor.fetchall()
            
            # Assign all permissions to admin
            for perm_id in permissions:
                cursor.execute("INSERT INTO user_permissions (user_id, permission_id) VALUES (%s, %s)",
                              (user_id, perm_id[0]))
            
            log_activity(f"User '{username}' registered as administrator with all permissions.")
        else:
            # Give regular users basic read and write permissions by default
            cursor.execute("SELECT id FROM permissions WHERE name IN ('read', 'write')")
            basic_permissions = cursor.fetchall()
            
            for perm_id in basic_permissions:
                cursor.execute("INSERT INTO user_permissions (user_id, permission_id) VALUES (%s, %s)",
                              (user_id, perm_id[0]))
            
            log_activity(f"User '{username}' registered with basic permissions.")
        
        # Commit the transaction
        mydb.commit()
        cursor.close()
        mydb.close()
        return True
    except mysql.IntegrityError as err:
        # Roll back in case of error
        mydb.rollback()
        log_activity(f"Registration failed: Database integrity error: {err}")
        cursor.close()
        mydb.close()
        return False  # Username already exists or other integrity error
    except Exception as err:
        # Roll back in case of error
        mydb.rollback()
        log_activity(f"Error registering user '{username}': {err}")
        cursor.close()
        mydb.close()
        return False


def login_user(username, password):
    """Verifies user credentials against the database and returns user information if valid.
    
    Args:
        username (str): The username to check
        password (str): The password to verify
        
    Returns:
        dict or False: Dictionary with user information if credentials are valid, False otherwise
    """
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        try:
            cursor.execute("SELECT id, password, role FROM users WHERE username = %s", (username,))
            result = cursor.fetchone()
            cursor.close()
            mydb.close()
            if result:
                user_id, stored_password, role = result
                hashed_password = hashlib.sha256(password.encode()).hexdigest()
                if hashed_password == stored_password:
                    log_activity(f"User '{username}' logged in successfully.")
                    # Return user information including role
                    return {
                        'id': user_id,
                        'username': username,
                        'role': role
                    }
                else:
                    log_activity(f"Login failed for user '{username}': Incorrect password.")
                    return False
            else:
                log_activity(f"Login failed: User '{username}' not found.")
                return False
        except Exception as err:
            log_activity(f"Error during login: {err}")
            cursor.close()
            mydb.close()
            return False
    return False


def get_user_public_key(username):
    """Fetch the recipient's public key from the database."""
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        try:
            cursor.execute("SELECT public_key FROM users WHERE username = %s", (username,))
            result = cursor.fetchone()
            cursor.close()
            mydb.close()
            if result:
                return result[0]  # Public key in PEM format
            return None
        except Exception as err:
            log_activity(f"Error retrieving public key: {err}")
            cursor.close()
            mydb.close()
            return None
    return None


def get_user_id(username):
    """Retrieves the user ID based on the username."""
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        try:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            result = cursor.fetchone()
            cursor.close()
            mydb.close()
            if result:
                return result[0]
            else:
                log_activity(f"Could not retrieve ID for user '{username}'.")
                return None
        except Exception as err:
            log_activity(f"Error retrieving user ID: {err}")
            cursor.close()
            mydb.close()
            return None
    return None


def get_username_by_id(user_id):
    """Retrieves the username based on the user ID."""
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        try:
            cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            result = cursor.fetchone()
            cursor.close()
            mydb.close()
            if result:
                return result[0]
            else:
                log_activity(f"Could not retrieve username for ID '{user_id}'.")
                return None
        except Exception as err:
            log_activity(f"Error retrieving username: {err}")
            cursor.close()
            mydb.close()
            return None
    return None


def get_user_role(user_id):
    """Retrieves the role of a user based on their user ID."""
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        try:
            cursor.execute("SELECT role FROM users WHERE id = %s", (user_id,))
            result = cursor.fetchone()
            cursor.close()
            mydb.close()
            if result:
                return result[0]
            else:
                log_activity(f"Could not retrieve role for user ID '{user_id}'.")
                return None
        except Exception as err:
            log_activity(f"Error retrieving user role: {err}")
            cursor.close()
            mydb.close()
            return None
    return None


def check_user_permission(user_id, permission_name):
    """Checks if a user has a specific permission.
    
    Args:
        user_id (int): The user's ID
        permission_name (str): The name of the permission to check
        
    Returns:
        bool: True if the user has the permission, False otherwise
    """
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        try:
            # If the user is an admin, they have all permissions
            cursor.execute("SELECT role FROM users WHERE id = %s", (user_id,))
            user_role = cursor.fetchone()
            
            if user_role and user_role[0] == 'admin':
                cursor.close()
                mydb.close()
                return True
                
            # Check specific permission
            cursor.execute("""
                SELECT COUNT(*) FROM user_permissions up
                JOIN permissions p ON up.permission_id = p.id
                WHERE up.user_id = %s AND p.name = %s
            """, (user_id, permission_name))
            
            has_permission = cursor.fetchone()[0] > 0
            cursor.close()
            mydb.close()
            return has_permission
        except Exception as err:
            log_activity(f"Error checking permission '{permission_name}' for user ID '{user_id}': {err}")
            cursor.close()
            mydb.close()
            return False
    return False


def get_transfer_history(user_id):
    """Retrieves the file transfer history for a given user ID."""
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        try:
            cursor.execute("""
                SELECT ft.filename, s.username AS sender, r.username AS recipient, ft.transfer_time, ft.file_size, ft.status
                FROM file_transfers ft
                JOIN users s ON ft.sender_id = s.id
                JOIN users r ON ft.recipient_id = r.id
                WHERE ft.sender_id = %s OR ft.recipient_id = %s
                ORDER BY ft.transfer_time DESC
            """, (user_id, user_id))
            history = cursor.fetchall()
            cursor.close()
            mydb.close()
            history_data = []
            for row in history:
                history_data.append({
                    'filename': row[0],
                    'sender': row[1],
                    'recipient': row[2],
                    'transfer_time': str(row[3]),
                    'file_size': row[4],
                    'status': row[5]
                })
            log_activity(f"Retrieved transfer history for user ID '{user_id}'. Found {len(history_data)} records.")
            return history_data
        except Exception as err:
            log_activity(f"Error retrieving transfer history: {err}")
            cursor.close()
            mydb.close()
            return None
    else:
        log_activity(f"Failed to retrieve transfer history for user ID '{user_id}' due to database error.")
        return None


def get_file_id(filename, user_id=None):
    """Retrieves the file ID based on filename.
    
    Args:
        filename (str): The filename to look up
        user_id (int, optional): If provided, only return files where this user is sender or recipient
        
    Returns:
        int or None: The file ID if found, None otherwise
    """
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        try:
            if user_id:
                cursor.execute("""
                    SELECT id FROM file_transfers 
                    WHERE filename = %s AND (sender_id = %s OR recipient_id = %s)
                """, (filename, user_id, user_id))
            else:
                cursor.execute("SELECT id FROM file_transfers WHERE filename = %s", (filename,))
                
            result = cursor.fetchone()
            cursor.close()
            mydb.close()
            
            if result:
                return result[0]
            else:
                log_activity(f"Could not find file ID for filename '{filename}'")
                return None
        except Exception as err:
            log_activity(f"Database error retrieving file ID: {err}")
            cursor.close()
            mydb.close()
            return None
    return None


def check_file_permission(file_id, user_id, permission_type):
    """Checks if a user has a specific permission for a file.
    
    Args:
        file_id (int): The file ID
        user_id (int): The user ID
        permission_type (str): The permission type ('read', 'write', 'manage')
        
    Returns:
        bool: True if the user has the permission, False otherwise
    """
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        try:
            # First check global read permission (required for any file operation)
            if not check_user_permission(user_id, permission_type):
                log_activity(f"User ID {user_id} lacks global {permission_type} permission")
                cursor.close()
                mydb.close()
                return False
                
            # Check if user is the sender (owners always have full permissions)
            cursor.execute("""
                SELECT sender_id FROM file_transfers
                WHERE id = %s
            """, (file_id,))
            result = cursor.fetchone()
            if not result:
                log_activity(f"File ID {file_id} not found in database")
                cursor.close()
                mydb.close()
                return False
                
            # File owner (sender) has all permissions
            if result[0] == user_id:
                cursor.close()
                mydb.close()
                return True
                
            # Check recipient permissions (recipients always have read access)
            cursor.execute("""
                SELECT recipient_id FROM file_transfers
                WHERE id = %s
            """, (file_id,))
            recipient_data = cursor.fetchone()
            
            # If user is the recipient and asking for read permission, grant it
            if recipient_data and recipient_data[0] == user_id and permission_type == 'read':
                cursor.close()
                mydb.close()
                return True
                
            # Check explicit file permissions
            cursor.execute("""
                SELECT COUNT(*) FROM file_permissions
                WHERE file_id = %s AND 
                      (user_id = %s OR is_public = TRUE) AND
                      permission_type = %s
            """, (file_id, user_id, permission_type))
            
            has_permission = cursor.fetchone()[0] > 0
            cursor.close()
            mydb.close()
            return has_permission
            
        except Exception as err:
            log_activity(f"Error checking file permission: {err}")
            cursor.close()
            mydb.close()
            return False
    return False


def get_file_permissions(file_id, user_id):
    """Retrieves the permissions for a specific file.
    
    Args:
        file_id (int): The file ID
        user_id (int): The ID of the user making the request
        
    Returns:
        dict or None: Dictionary with permissions data if successful, None otherwise
    """
    # Check if user has permission to view permissions
    mydb = create_db_connection()
    if not mydb:
        return None
        
    cursor = mydb.cursor()
    try:
        # Check if user is file owner (sender)
        cursor.execute("SELECT sender_id FROM file_transfers WHERE id = %s", (file_id,))
        result = cursor.fetchone()
        is_file_owner = result and result[0] == user_id
        
        # If user is not file owner, check if they have manage_files permission
        # File owners should always be able to manage their own files' permissions
        if not is_file_owner and not check_user_permission(user_id, 'manage_files'):
            log_activity(f"User ID {user_id} attempted to view file permissions without permission")
            cursor.close()
            mydb.close()
            return None
            
        # Get user-specific permissions
        cursor.execute("""
            SELECT u.username, fp.permission_type 
            FROM file_permissions fp
            JOIN users u ON fp.user_id = u.id
            WHERE fp.file_id = %s AND fp.user_id IS NOT NULL
        """, (file_id,))
        user_permissions = cursor.fetchall()
        
        # Get public permissions
        cursor.execute("""
            SELECT permission_type 
            FROM file_permissions
            WHERE file_id = %s AND is_public = TRUE
        """, (file_id,))
        public_permissions = cursor.fetchall()
        
        cursor.close()
        mydb.close()
        
        # Format permissions data
        permissions_data = {
            'user_permissions': [{'username': row[0], 'permission': row[1]} for row in user_permissions],
            'public_permissions': [row[0] for row in public_permissions]
        }
        
        return permissions_data
    except Exception as err:
        log_activity(f"Error retrieving file permissions: {err}")
        cursor.close()
        mydb.close()
        return None


def set_file_permission(file_id, user_id, permission_type, target_user_id=None, is_public=False):
    """Sets a permission for a file.
    
    Args:
        file_id (int): The file ID
        user_id (int): The ID of the user setting the permission
        permission_type (str): The permission type ('read', 'write', 'manage')
        target_user_id (int, optional): The ID of the user to grant permission to
        is_public (bool, optional): Whether this is a public permission
        
    Returns:
        bool: True if permission was set, False otherwise
    """
    # Validate permission type
    if permission_type not in ['read', 'write', 'manage']:
        log_activity(f"Invalid permission type requested: {permission_type}")
        return False
        
    # Check if user has permission to set file permissions
    mydb = create_db_connection()
    if not mydb:
        return False
        
    cursor = mydb.cursor()
    try:
        # Check if user is file owner (sender)
        cursor.execute("SELECT sender_id FROM file_transfers WHERE id = %s", (file_id,))
        result = cursor.fetchone()
        is_file_owner = result and result[0] == user_id
        
        # If user is not file owner, check if they have manage_files permission
        if not is_file_owner and not check_user_permission(user_id, 'manage_files'):
            log_activity(f"User ID {user_id} attempted to set file permission without permission")
            cursor.close()
            mydb.close()
            return False
        
        # Check if permission already exists
        if target_user_id:
            cursor.execute("""
                SELECT COUNT(*) FROM file_permissions 
                WHERE file_id = %s AND user_id = %s AND permission_type = %s
            """, (file_id, target_user_id, permission_type))
        else:
            cursor.execute("""
                SELECT COUNT(*) FROM file_permissions 
                WHERE file_id = %s AND is_public = TRUE AND permission_type = %s
            """, (file_id, permission_type))
            
        if cursor.fetchone()[0] > 0:
            # Permission already exists
            cursor.close()
            mydb.close()
            return True
            
        # Set permission
        cursor.execute("""
            INSERT INTO file_permissions (file_id, user_id, permission_type, is_public)
            VALUES (%s, %s, %s, %s)
        """, (file_id, target_user_id, permission_type, is_public))
        
        mydb.commit()
        log_activity(f"User ID {user_id} set {permission_type} permission for file ID {file_id}")
        cursor.close()
        mydb.close()
        return True
        
    except Exception as err:
        log_activity(f"Error setting file permission: {err}")
        cursor.close()
        mydb.close()
        return False


def remove_file_permission(file_id, user_id, permission_type, target_user_id=None, is_public=False):
    """Removes a permission from a file.
    
    Args:
        file_id (int): The file ID
        user_id (int): The ID of the user removing the permission
        permission_type (str): The permission type ('read', 'write', 'manage')
        target_user_id (int, optional): The ID of the user to remove permission from
        is_public (bool, optional): Whether this is a public permission
        
    Returns:
        bool: True if permission was removed, False otherwise
    """
    # Check if user has permission to remove file permissions
    mydb = create_db_connection()
    if not mydb:
        return False
        
    cursor = mydb.cursor()
    try:
        # Check if user is file owner (sender)
        cursor.execute("SELECT sender_id FROM file_transfers WHERE id = %s", (file_id,))
        result = cursor.fetchone()
        is_file_owner = result and result[0] == user_id
        
        # If user is not file owner, check if they have manage_files permission
        if not is_file_owner and not check_user_permission(user_id, 'manage_files'):
            log_activity(f"User ID {user_id} attempted to remove file permission without permission")
            cursor.close()
            mydb.close()
            return False
            
        # Remove permission
        if target_user_id:
            cursor.execute("""
                DELETE FROM file_permissions 
                WHERE file_id = %s AND user_id = %s AND permission_type = %s
            """, (file_id, target_user_id, permission_type))
        else:
            cursor.execute("""
                DELETE FROM file_permissions 
                WHERE file_id = %s AND is_public = TRUE AND permission_type = %s
            """, (file_id, permission_type))
            
        affected_rows = cursor.rowcount
        mydb.commit()
        
        if affected_rows > 0:
            log_activity(f"User ID {user_id} removed {permission_type} permission for file ID {file_id}")
            
        cursor.close()
        mydb.close()
        return True
        
    except Exception as err:
        log_activity(f"Error removing file permission: {err}")
        cursor.close()
        mydb.close()
        return False


def get_all_users():
    """Retrieves a list of all users in the system.
    
    Returns:
        list: List of dictionaries containing user information
    """
    mydb = create_db_connection()
    if mydb:
        cursor = mydb.cursor()
        try:
            cursor.execute("SELECT id, username, role FROM users ORDER BY username")
            results = cursor.fetchall()
            cursor.close()
            mydb.close()
            
            users = []
            for user_id, username, role in results:
                users.append({
                    'id': user_id,
                    'username': username,
                    'role': role
                })
            
            return users
        except Exception as err:
            log_activity(f"Error retrieving users: {err}")
            cursor.close()
            mydb.close()
            return None
        return None


def grant_permission(user_id, target_user_id, permission_name):
    """Grants a permission to a user.
    
    Args:
        user_id (int): The ID of the user granting the permission (must be admin)
        target_user_id (int): The ID of the user to grant the permission to
        permission_name (str): The name of the permission to grant
        
    Returns:
        bool: True if permission was granted, False otherwise
    """
    # Check if the user has permission to grant permissions (must be admin)
    if not check_user_permission(user_id, 'manage_users'):
        log_activity(f"User ID {user_id} attempted to grant permission without manage_users permission")
        return False
        
    mydb = create_db_connection()
    if not mydb:
        return False
        
    cursor = mydb.cursor()
    try:
        # Check if permission exists
        cursor.execute("SELECT id FROM permissions WHERE name = %s", (permission_name,))
        permission_result = cursor.fetchone()
        if not permission_result:
            log_activity(f"Invalid permission name: {permission_name}")
            cursor.close()
            mydb.close()
            return False
            
        permission_id = permission_result[0]
        
        # Check if user already has this permission
        cursor.execute("""
            SELECT COUNT(*) FROM user_permissions 
            WHERE user_id = %s AND permission_id = %s
        """, (target_user_id, permission_id))
        
        if cursor.fetchone()[0] > 0:
            # User already has this permission
            cursor.close()
            mydb.close()
            return True
            
        # Grant the permission
        cursor.execute("""
            INSERT INTO user_permissions (user_id, permission_id)
            VALUES (%s, %s)
        """, (target_user_id, permission_id))
        
        mydb.commit()
        log_activity(f"User ID {user_id} granted '{permission_name}' permission to user ID {target_user_id}")
        cursor.close()
        mydb.close()
        return True
    except Exception as err:
        log_activity(f"Error granting permission: {err}")
        cursor.close()
        mydb.close()
        return False


def revoke_permission(user_id, target_user_id, permission_name):
    """Revokes a permission from a user.
    
    Args:
        user_id (int): The ID of the user revoking the permission (must be admin)
        target_user_id (int): The ID of the user to revoke the permission from
        permission_name (str): The name of the permission to revoke
        
    Returns:
        bool: True if permission was revoked, False otherwise
    """
    # Check if the user has permission to revoke permissions (must be admin)
    if not check_user_permission(user_id, 'manage_users'):
        log_activity(f"User ID {user_id} attempted to revoke permission without manage_users permission")
        return False
        
    mydb = create_db_connection()
    if not mydb:
        return False
        
    cursor = mydb.cursor()
    try:
        # Check if permission exists
        cursor.execute("SELECT id FROM permissions WHERE name = %s", (permission_name,))
        permission_result = cursor.fetchone()
        if not permission_result:
            log_activity(f"Invalid permission name: {permission_name}")
            cursor.close()
            mydb.close()
            return False
            
        permission_id = permission_result[0]
        
        # Revoke the permission
        cursor.execute("""
            DELETE FROM user_permissions 
            WHERE user_id = %s AND permission_id = %s
        """, (target_user_id, permission_id))
        
        affected_rows = cursor.rowcount
        mydb.commit()
        
        if affected_rows > 0:
            log_activity(f"User ID {user_id} revoked '{permission_name}' permission from user ID {target_user_id}")
        
        cursor.close()
        mydb.close()
        return True
    except Exception as err:
        log_activity(f"Error revoking permission: {err}")
        cursor.close()
        mydb.close()
        return False


# --- Client Handling ---
def handle_client(client_socket, client_address):
    """Handles communication with a connected client."""
    log_activity(f"Connection from {client_address}")

    logged_in_user = None

    try:
        while True:
            try:
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    log_activity(f"Client {client_address} disconnected.")
                    break

                try:
                    request = json.loads(data.decode(ENCODING))
                    action = request.get('action')
                    log_activity(
                        f"Received action '{action}' from {client_address} (User: {logged_in_user if logged_in_user else 'N/A'}). Request details: {request}")

                    if action == 'check_username':
                        username = request.get('username')
                        if username:
                            exists = check_username_exists(username)
                            response = {'status': 'success', 'exists': exists}
                        else:
                            response = {'status': 'error', 'message': 'Username parameter is required'}
                        client_socket.send(json.dumps(response).encode(ENCODING))
                        log_activity(f"Sent username check response to {client_address}: {response}")
                        
                    elif action == 'register':
                        username = request.get('username')
                        password = request.get('password')
                        client_public_key = request.get('public_key')
                        requested_role = request.get('role', 'regular')
                        
                        if username and password and client_public_key:
                            # Get requester ID if logged in (for admin registration)
                            requester_id = None
                            if logged_in_user:
                                requester_id = get_user_id(logged_in_user)
                                
                            if register_user(username, password, client_public_key, requested_role, requester_id):
                                response = {'status': 'success', 'message': 'Registration successful'}
                            else:
                                if requested_role == 'admin':
                                    response = {'status': 'error', 'message': 'Registration failed: Not authorized to create admin account'}
                                else:
                                    response = {'status': 'error', 'message': 'Registration failed: Username already exists'}
                        else:
                            response = {'status': 'error', 'message': 'Username, password and public key are required'}
                        client_socket.send(json.dumps(response).encode(ENCODING))
                        log_activity(f"Sent response to {client_address}: {response}")

                    elif action == 'login':
                        username = request.get('username')
                        password = request.get('password')
                        if username and password:
                            login_result = login_user(username, password)
                            if login_result:
                                logged_in_user = username
                                response = {
                                    'status': 'success', 
                                    'message': 'Login successful',
                                    'user_id': login_result['id'],
                                    'username': login_result['username'],
                                    'role': login_result['role']
                                }
                            else:
                                response = {'status': 'error', 'message': 'Invalid username or password'}
                        else:
                            response = {'status': 'error', 'message': 'Username and password are required'}
                        client_socket.send(json.dumps(response).encode(ENCODING))
                        log_activity(f"Sent response to {client_address}: {response}")

                    elif action == 'send_file' and logged_in_user:
                        recipient_username = request.get('recipient')
                        filename = request.get('filename')
                        file_size = request.get('file_size')
                        encrypted_key = request.get('encrypted_key')
                        original_hash = request.get('original_hash')  # Get original file hash

                        # Input validation
                        if not all([recipient_username, filename, file_size is not None, encrypted_key]):
                            response = {'status': 'error', 'message': 'Missing required parameters'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue

                        # Validate recipient and sender
                        recipient_id = get_user_id(recipient_username)
                        sender_id = get_user_id(logged_in_user)

                        if not recipient_id or not sender_id:
                            response = {'status': 'error', 'message': f'Invalid recipient or sender'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue

                        # Check if sender has write permission
                        if not check_user_permission(sender_id, 'write'):
                            response = {'status': 'error', 'message': 'Access denied: You do not have permission to send files'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                            
                        # Check if recipient has read permission
                        if not check_user_permission(recipient_id, 'read'):
                            response = {'status': 'error', 'message': f'Access denied: User {recipient_username} does not have permission to receive files'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue

                        # Ready to receive file
                        try:
                            response = {'status': 'ready', 'message': 'Ready to receive file'}
                            client_socket.send(json.dumps(response).encode(ENCODING))

                            # Set a timeout for file reception
                            client_socket.settimeout(60)  # 60-second timeout

                            # Receive encrypted file data with progress tracking
                            received_data = b""
                            bytes_received = 0
                            start_time = datetime.now()

                            try:
                                while bytes_received < file_size:
                                    chunk = client_socket.recv(BUFFER_SIZE)
                                    if not chunk:
                                        break
                                    received_data += chunk
                                    bytes_received += len(chunk)

                                    # Log progress for large files
                                    if file_size > 1048576 and bytes_received % 1048576 == 0:  # Every 1MB
                                        elapsed = (datetime.now() - start_time).total_seconds()
                                        speed = bytes_received / elapsed if elapsed > 0 else 0
                                        log_activity(f"Receiving '{filename}': {bytes_received/file_size*100:.1f}% complete ({speed/1024:.1f} KB/s)")
                            finally:
                                # Reset socket timeout
                                client_socket.settimeout(None)

                            # Verify file size
                            if bytes_received != file_size:
                                log_activity(f"File transfer incomplete: received {bytes_received}/{file_size} bytes")
                                response = {'status': 'error', 'message': 'File transfer incomplete'}
                                client_socket.send(json.dumps(response).encode(ENCODING))
                                continue

                            # Save file and record in database
                            try:
                                # Create directory if needed
                                os.makedirs("received_files", exist_ok=True)
                                
                                # Generate unique filename to prevent overwrites
                                safe_filename = f"{logged_in_user}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}.enc"
                                save_path = os.path.join("received_files", safe_filename)
                                
                                # Save encrypted file
                                with open(save_path, 'wb') as f:
                                    f.write(received_data)

                                # Store in database with integrity hash
                                mydb = create_db_connection()
                                if not mydb:
                                    raise Exception("Database connection failed")
                                    
                                cursor = mydb.cursor()
                                try:
                                    # Add original_hash to the database record if provided
                                    if original_hash:
                                        cursor.execute("""
                                            INSERT INTO file_transfers 
                                            (sender_id, recipient_id, filename, file_size, status, encrypted_key, original_hash)
                                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                                        """, (sender_id, recipient_id, filename, len(received_data), 'success',
                                            encrypted_key, original_hash))
                                    else:
                                        cursor.execute("""
                                            INSERT INTO file_transfers 
                                            (sender_id, recipient_id, filename, file_size, status, encrypted_key)
                                            VALUES (%s, %s, %s, %s, %s, %s)
                                        """, (sender_id, recipient_id, filename, len(received_data), 'success',
                                            encrypted_key))
                                    mydb.commit()
                                    
                                    # Get the file ID for setting permissions
                                    file_id = cursor.lastrowid
                                    
                                    # Set initial file permissions
                                    # Owner (sender) gets all permissions
                                    for perm_type in ['read', 'write', 'manage']:
                                        cursor.execute("""
                                            INSERT INTO file_permissions (file_id, user_id, permission_type, is_public)
                                            VALUES (%s, %s, %s, %s)
                                        """, (file_id, sender_id, perm_type, False))
                                    
                                    # Recipient gets read permission
                                    cursor.execute("""
                                        INSERT INTO file_permissions (file_id, user_id, permission_type, is_public)
                                        VALUES (%s, %s, %s, %s)
                                    """, (file_id, recipient_id, 'read', False))
                                    
                                    # Log the permissions assignment
                                    log_activity(f"File permissions set: sender {sender_id} (all permissions), recipient {recipient_id} (read permission)")
                                    
                                    mydb.commit()
                                    log_activity(f"Initial file permissions set for file ID {file_id}")
                                except Exception as err:
                                    log_activity(f"Database error: {err}")
                                    raise Exception(f"Database error: {err}")
                                finally:
                                    cursor.close()
                                    mydb.close()

                                # Send success response
                                log_activity(f"File '{filename}' ({bytes_received} bytes) successfully received from '{logged_in_user}' for '{recipient_username}'")
                                response = {'status': 'success', 'message': f'File transfer completed successfully'}
                                
                            except Exception as e:
                                log_activity(f"Error storing file: {e}")
                                response = {'status': 'error', 'message': f'Server error: {str(e)}'}
                                
                        except Exception as e:
                            log_activity(f"Error handling file transfer: {e}")
                            response = {'status': 'error', 'message': 'Server error during transfer'}
                            
                        # Send final response
                        client_socket.send(json.dumps(response).encode(ENCODING))

                    elif action == 'get_history' and logged_in_user:
                        user_id = get_user_id(logged_in_user)
                        if user_id:
                            history = get_transfer_history(user_id)
                            if history is not None:
                                response = {'status': 'success', 'history': history}
                            else:
                                response = {'status': 'error', 'message': 'Could not retrieve transfer history'}
                        else:
                            response = {'status': 'error', 'message': 'User not found'}
                        client_socket.send(json.dumps(response).encode(ENCODING))
                        log_activity(f"Sent transfer history response to {client_address} (User: {logged_in_user}).")

                    elif action == 'get_public_key':
                        recipient_username = request.get('recipient')
                        recipient_public_key = get_user_public_key(recipient_username)

                        if recipient_public_key:
                            response = {'status': 'success', 'public_key': recipient_public_key}
                        else:
                            response = {'status': 'error', 'message': 'Recipient not found'}

                        client_socket.send(json.dumps(response).encode(ENCODING))

                    elif action == 'download_file' and logged_in_user:
                        filename = request.get('filename')
                        recipient_username = logged_in_user
                        user_id = get_user_id(logged_in_user)

                        if not filename:
                            response = {'status': 'error', 'message': 'Filename not provided'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                            
                        # Check if user has read permission
                        if not check_user_permission(user_id, 'read'):
                            response = {'status': 'error', 'message': 'Access denied: You do not have permission to download files'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue

                        # Get file ID to check permissions
                        file_id = get_file_id(filename)
                        if not file_id:
                            response = {'status': 'error', 'message': 'File not found'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue

                        # Check if user has permission to download this specific file
                        if not check_file_permission(file_id, user_id, 'read'):
                            response = {'status': 'error', 'message': 'Access denied: You do not have permission to download this file'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue

                        try:
                            # Connect to database and get file metadata
                            mydb = create_db_connection()
                            if not mydb:
                                response = {'status': 'error', 'message': 'Database connection failed'}
                                client_socket.send(json.dumps(response).encode(ENCODING))
                                continue
                                
                            cursor = mydb.cursor()
                            try:
                                # Query file metadata and integrity hash
                                cursor.execute("""
                                    SELECT file_size, encrypted_key, original_hash
                                    FROM file_transfers
                                    WHERE filename = %s AND recipient_id = (SELECT id FROM users WHERE username = %s)
                                """, (filename, recipient_username))
                                result = cursor.fetchone()
                            except Exception as err:
                                log_activity(f"Database error: {err}")
                                response = {'status': 'error', 'message': f'Database error: {str(err)}'}
                                client_socket.send(json.dumps(response).encode(ENCODING))
                                continue
                            finally:
                                cursor.close()
                                mydb.close()

                            if not result:
                                response = {'status': 'error', 'message': 'No record found for this file'}
                                client_socket.send(json.dumps(response).encode(ENCODING))
                                continue
                                
                            # Extract file metadata
                            if len(result) >= 3:
                                file_size, encrypted_key, original_hash = result[0], result[1], result[2]
                            else:
                                file_size, encrypted_key = result[0], result[1]
                                original_hash = None

                            # Locate encrypted file
                            file_path = None
                            try:
                                for fname in os.listdir("received_files"):
                                    if fname.endswith(f"_{filename}.enc"):
                                        file_path = os.path.join("received_files", fname)
                                        break
                            except Exception as e:
                                log_activity(f"Error searching for file: {e}")
                                response = {'status': 'error', 'message': 'Server error locating file'}
                                client_socket.send(json.dumps(response).encode(ENCODING))
                                continue

                            if not file_path or not os.path.exists(file_path):
                                log_activity(f"File not found: {filename}")
                                response = {'status': 'error', 'message': 'File not found on server'}
                                client_socket.send(json.dumps(response).encode(ENCODING))
                                continue

                            # Read and send file data
                            try:
                                # Read encrypted file
                                with open(file_path, 'rb') as f:
                                    encrypted_data = f.read()

                                # Prepare response with metadata and integrity hash
                                response_data = {
                                    'status': 'success',
                                    'file_size': len(encrypted_data),
                                    'encrypted_key': encrypted_key
                                }
                                
                                # Include original hash if available (for integrity verification)
                                if original_hash:
                                    response_data['original_hash'] = original_hash

                                # Send metadata first
                                client_socket.send(json.dumps(response_data).encode(ENCODING))

                                # Then send the file data
                                client_socket.sendall(encrypted_data)

                                log_activity(f"File '{filename}' ({len(encrypted_data)} bytes) sent to '{recipient_username}'")
                            except Exception as e:
                                log_activity(f"Error sending file: {e}")
                                response = {'status': 'error', 'message': f'Error reading or sending file: {str(e)}'}
                                client_socket.send(json.dumps(response).encode(ENCODING))
                                
                        except Exception as e:
                            log_activity(f"Unexpected error during file download: {e}")
                            response = {'status': 'error', 'message': 'Server error'}
                            client_socket.send(json.dumps(response).encode(ENCODING))

                    elif action == 'logout' and logged_in_user:
                        log_activity(f"User '{logged_in_user}' logged out.")
                        logged_in_user = None
                        response = {'status': 'success', 'message': 'Logged out successfully'}
                        client_socket.send(json.dumps(response).encode(ENCODING))
                        log_activity(f"Sent logout confirmation to {client_address}.")
                        
                    elif action == 'set_file_permission' and logged_in_user:
                        filename = request.get('filename')
                        permission_type = request.get('permission_type')
                        target_username = request.get('target_username')
                        is_public = request.get('is_public', False)
                        
                        # Input validation
                        if not filename or not permission_type or (not target_username and not is_public):
                            response = {'status': 'error', 'message': 'Missing required parameters'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                            
                        # Validate permission type
                        if permission_type not in ['read', 'write', 'manage']:
                            response = {'status': 'error', 'message': 'Invalid permission type'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                        
                        # Get file ID
                        file_id = get_file_id(filename)
                        if not file_id:
                            response = {'status': 'error', 'message': 'File not found'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                            
                        # Get user IDs
                        user_id = get_user_id(logged_in_user)
                        target_user_id = get_user_id(target_username) if target_username else None
                        
                        if target_username and not target_user_id:
                            response = {'status': 'error', 'message': f'Target user {target_username} not found'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                            
                        # Set permission
                        if set_file_permission(file_id, user_id, permission_type, target_user_id, is_public):
                            response = {'status': 'success', 'message': 'Permission set successfully'}
                        else:
                            response = {'status': 'error', 'message': 'Failed to set permission. Check if you have the required permissions.'}
                            
                        client_socket.send(json.dumps(response).encode(ENCODING))
                        
                    elif action == 'remove_file_permission' and logged_in_user:
                        filename = request.get('filename')
                        permission_type = request.get('permission_type')
                        target_username = request.get('target_username')
                        is_public = request.get('is_public', False)
                        
                        # Input validation
                        if not filename or not permission_type or (not target_username and not is_public):
                            response = {'status': 'error', 'message': 'Missing required parameters'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                            
                        # Validate permission type
                        if permission_type not in ['read', 'write', 'manage']:
                            response = {'status': 'error', 'message': 'Invalid permission type'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                        
                        # Get file ID
                        file_id = get_file_id(filename)
                        if not file_id:
                            response = {'status': 'error', 'message': 'File not found'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                            
                        # Get user IDs
                        user_id = get_user_id(logged_in_user)
                        target_user_id = get_user_id(target_username) if target_username else None
                        
                        if target_username and not target_user_id:
                            response = {'status': 'error', 'message': f'Target user {target_username} not found'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                            
                        # Remove permission
                        if remove_file_permission(file_id, user_id, permission_type, target_user_id, is_public):
                            response = {'status': 'success', 'message': 'Permission removed successfully'}
                        else:
                            response = {'status': 'error', 'message': 'Failed to remove permission. Check if you have the required permissions.'}
                            
                        client_socket.send(json.dumps(response).encode(ENCODING))
                        
                    elif action == 'get_file_permissions' and logged_in_user:
                        filename = request.get('filename')
                        
                        if not filename:
                            response = {'status': 'error', 'message': 'Filename is required'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                            
                        # Get file ID
                        file_id = get_file_id(filename)
                        if not file_id:
                            response = {'status': 'error', 'message': 'File not found'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                            
                        # Get user ID
                        user_id = get_user_id(logged_in_user)
                        
                        # Get file permissions
                        permissions_data = get_file_permissions(file_id, user_id)
                        
                        if permissions_data:
                            response = {'status': 'success', 'permissions': permissions_data}
                        else:
                            response = {'status': 'error', 'message': 'Access denied: You do not have permission to view file permissions'}
                            
                        client_socket.send(json.dumps(response).encode(ENCODING))

                    elif action == 'get_users' and logged_in_user:
                        # Only admin users can get the user list
                        user_id = get_user_id(logged_in_user)
                        if not user_id or not check_user_permission(user_id, 'manage_users'):
                            response = {'status': 'error', 'message': 'Access denied: You do not have permission to manage users'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                            
                        users = get_all_users()
                        if users is not None:
                            response = {'status': 'success', 'users': users}
                        else:
                            response = {'status': 'error', 'message': 'Failed to retrieve user list'}
                            
                        client_socket.send(json.dumps(response).encode(ENCODING))

                    elif action == 'grant_permission' and logged_in_user:
                        target_username = request.get('target_username')
                        permission_name = request.get('permission')
                        
                        if not target_username or not permission_name:
                            response = {'status': 'error', 'message': 'Missing required parameters'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                            
                        # Get user IDs
                        user_id = get_user_id(logged_in_user)
                        target_user_id = get_user_id(target_username)
                        
                        if not user_id or not target_user_id:
                            response = {'status': 'error', 'message': 'Invalid user or target user'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                            
                        # Grant permission
                        if grant_permission(user_id, target_user_id, permission_name):
                            response = {'status': 'success', 'message': f"Permission '{permission_name}' granted to {target_username}"}
                        else:
                            response = {'status': 'error', 'message': 'Failed to grant permission'}
                            
                        client_socket.send(json.dumps(response).encode(ENCODING))

                    elif action == 'revoke_permission' and logged_in_user:
                        target_username = request.get('target_username')
                        permission_name = request.get('permission')
                        
                        if not target_username or not permission_name:
                            response = {'status': 'error', 'message': 'Missing required parameters'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                            
                        # Get user IDs
                        user_id = get_user_id(logged_in_user)
                        target_user_id = get_user_id(target_username)
                        
                        if not user_id or not target_user_id:
                            response = {'status': 'error', 'message': 'Invalid user or target user'}
                            client_socket.send(json.dumps(response).encode(ENCODING))
                            continue
                            
                        # Revoke permission
                        if revoke_permission(user_id, target_user_id, permission_name):
                            response = {'status': 'success', 'message': f"Permission '{permission_name}' revoked from {target_username}"}
                        else:
                            response = {'status': 'error', 'message': 'Failed to revoke permission'}
                            
                        client_socket.send(json.dumps(response).encode(ENCODING))

                    else:
                        response = {'status': 'error', 'message': 'Invalid action or not logged in'}
                        client_socket.send(json.dumps(response).encode(ENCODING))
                        log_activity(f"Sent error response to {client_address}: {response}")

                except json.JSONDecodeError:
                    response = {'status': 'error', 'message': 'Invalid JSON format'}
                    client_socket.send(json.dumps(response).encode(ENCODING))
                    log_activity(f"Sent JSON decode error to {client_address}: {response}")

            except ConnectionResetError:
                log_activity(f"Client {client_address} disconnected unexpectedly.")
                break
            except Exception as e:
                log_activity(f"Error handling client {client_address}: {e}")
                break

    finally:
        log_activity(f"Connection with {client_address} closed.")
        client_socket.close()


# --- Server Startup ---
def start_server():
    """Starts the file transfer server."""
    # Create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((SERVER_HOST, SERVER_PORT))
        server_socket.listen(5)
        log_activity(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")
        
        # Initialize database tables
        create_tables()
        
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.daemon = True
            client_thread.start()
    except Exception as e:
        log_activity(f"Server error: {e}")
    finally:
        server_socket.close()
        log_activity("Server socket closed.")


if __name__ == "__main__":
    start_server()