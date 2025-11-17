"""
Pydantic models for protocol messages and network helper functions.
"""

import json
import socket
from pydantic import BaseModel
from typing import Union, Optional

# --- Pydantic Models ---

class AuthSuccessMessage(BaseModel):
    status: str = "auth_success"
    message: str

class ErrorMessage(BaseModel):
    error: str

# Models for Step 2B: Secure Credentials (Req 2.2)

class TempDHClientHello(BaseModel):
    """
    Client -> Server message for temporary DH exchange.
    Contains the client's public parameters p, g, and public value A.
    """
    type: str = "temp_dh_hello"
    p: int
    g: int
    A_y: int

class TempDHServerReply(BaseModel):
    """
    Server -> Client response for temporary DH exchange.
    Contains the server's public value B.
    """
    type: str = "temp_dh_reply"
    B_y: int


class DHClient(BaseModel):
    """
    Client -> Server message for FINAL session key (Req 2.3 / Sec 1.2).
    Contains p, g, and public value A.
    """
    type: str = "dh_client" 
    p: int
    g: int
    A_y: int 

class DHServer(BaseModel):
    """
    Server -> Client response for FINAL session key (Req 2.3 / Sec 1.2).
    Contains public value B.
    """
    type: str = "dh_server" 
    B_y: int 

class SecureRegister(BaseModel):
    """
    Client -> Server encrypted message for registration.
    """
    type: str = "register"
    email: str
    username: str
    password: str

class SecureLogin(BaseModel):
    """
    Client -> Server encrypted message for login.
    """
    type: str = "login"
    username: str
    password: str

class StatusMessage(BaseModel):
    """
    Server -> Client encrypted message for status (e.g., login ok/fail).
    """
    type: str = "status"
    success: bool
    message: str

#phase 4
class ChatMessage(BaseModel):
    """
    Client <-> Server message for an encrypted chat message.
    Corresponds to "msg" in the spec (Req 2.4.i).
    """
    type: str = "msg"
    seqno: int     # Sequence number (for replay protection)
    ts: int        # Timestamp (milliseconds)
    ct: str        # Base64-encoded AES-128 ciphertext
    sig: str       # Base64-encoded RSA signature
#phase 5
class SessionReceiptMessage(BaseModel):
    """
    Client <-> Server message to exchange the final session receipt.
    (Req 2.5.ii)
    """
    type: str = "receipt"
    sig: str# Base64-encoded signature of the TranscriptHash
      
# --- Network Helper Functions (Unchanged) ---
# (Your existing send_message, receive_message, 
#  send_json_message, and receive_json_message functions go here)

def send_message(sock: socket.socket, message_bytes: bytes):
    """Prefixes message with 4-byte length and sends it."""
    try:
        message_len_bytes = len(message_bytes).to_bytes(4, 'big')
        sock.sendall(message_len_bytes + message_bytes)
    except (socket.error, OverflowError) as e:
        print(f"Error sending message: {e}")
        raise

def receive_message(sock: socket.socket) -> Union[bytes, None]:
    """Reads 4-byte length prefix and returns the raw bytes message."""
    try:
        # Read the 4-byte length prefix
        message_len_bytes = sock.recv(4)
        if not message_len_bytes:
            print("Connection closed by peer (no length).")
            return None
        message_len = int.from_bytes(message_len_bytes, 'big')

        # Read the full message
        message_data = b""
        while len(message_data) < message_len:
            chunk = sock.recv(message_len - len(message_data))
            if not chunk:
                print("Connection closed by peer (incomplete message).")
                return None  # Connection lost
        
        return message_data
    
    except socket.timeout:
        # --- THIS IS THE FIX ---
        # A timeout is normal. Re-raise it so the
        # chat.py loop can catch it and 'continue'.
        raise
    
    except socket.error as e:
        # Handle other, real socket errors
        print(f"Socket error while receiving: {e}")
        return None
    
    
def send_json_message(sock: socket.socket, message: BaseModel):
    """Serializes a Pydantic model to JSON and sends it."""
    json_bytes = message.model_dump_json().encode('utf-8')
    send_message(sock, json_bytes)

def receive_json_message(sock: socket.socket) -> Union[dict, None]:
    """Receives bytes, decodes UTF-8, and parses JSON into a dict."""
    message_bytes = receive_message(sock)
    if message_bytes is None:
        return None
    try:
        return json.loads(message_bytes.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"Error decoding JSON message: {e}")
        return None