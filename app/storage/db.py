"""
MySQL users table + salted hashing (no chat storage).
"""

import mysql.connector
import os
import hashlib
import hmac # For constant-time string comparison

# --- Database Connection ---

def get_db_connection():
    """Establishes a connection to the MySQL database."""
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",      
            password="",      
            database="securechat_db"
        )
        return conn
    except mysql.connector.Error as e:
        print(f"Error connecting to MySQL database: {e}")
        print("Please ensure MySQL is running and credentials are correct.")
        exit(1)

# --- Password Hashing (Requirement 2.2.5) ---

def _hash_password(salt: bytes, password: str) -> str:
    """
    Computes the salted password hash: hex(SHA256(salt || password))
    """
    hasher = hashlib.sha256()
    hasher.update(salt)
    hasher.update(password.encode('utf-8'))
    return hasher.hexdigest() # Returns a 64-char hex string

# --- Public Functions ---

def register_user(email: str, username: str, password: str) -> bool:
    """
    Registers a new user in the database.
    Generates a salt, hashes the password, and stores the user.
    Returns True on success, raises Exception on failure.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Check if user already exists
    cursor.execute(
        "SELECT username FROM users WHERE username = %s OR email = %s",
        (username, email)
    )
    if cursor.fetchone():
        cursor.close()
        conn.close()
        raise Exception(f"Username '{username}' or email '{email}' already exists.")
        
    # 2. Generate 16-byte random salt (Req 2.2.5)
    salt = os.urandom(16)
    
    # 3. Compute salted hash
    pwd_hash = _hash_password(salt, password)
    
    # 4. Store in database
    try:
        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )
        conn.commit()
        print(f"[DB] Successfully registered user: {username}")
        return True
    except mysql.connector.Error as e:
        conn.rollback()
        raise Exception(f"Database error during registration: {e}")
    finally:
        cursor.close()
        conn.close()

def verify_login(username: str, password: str) -> bool:
    """
    Verifies a user's login credentials.
    Fetches salt/hash from DB and performs a constant-time comparison.
    Returns True on success, False on failure.
    """
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True) # Fetch as dict
    
    # 1. Fetch user's salt and stored hash
    try:
        cursor.execute(
            "SELECT salt, pwd_hash FROM users WHERE username = %s",
            (username,)
        )
        user = cursor.fetchone()
        
        if not user:
            print(f"[DB] Login failed: User '{username}' not found.")
            return False
            
        salt = user['salt']
        stored_hash = user['pwd_hash']
        
        # 2. Re-compute hash with provided password
        computed_hash = _hash_password(salt, password)
        
        # 3. Compare hashes in constant time (Req 2.2.7 / Rubric)
        # This prevents timing attacks
        if hmac.compare_digest(stored_hash, computed_hash):
            print(f"[DB] Login successful for user: {username}")
            return True
        else:
            print(f"[DB] Login failed: Invalid password for user: {username}")
            return False
            
    except mysql.connector.Error as e:
        print(f"Database error during login: {e}")
        return False
    finally:
        cursor.close()
        conn.close()