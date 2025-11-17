"""
Server main logic.
Handles mutual auth, temporary DH, and secure credential processing.
"""

import socket
import json
import time
from typing import Union
from .common import protocol
from .crypto import pki, dh, aes
from .storage import db, transcript
from . import chat

def handle_secure_credentials(conn: socket.socket, temp_aes_key: bytes) -> Union[str, None]:
    """
    Handles encrypted registration or login (Req 2.2.4).
    Returns the username on successful login, None otherwise.
    """
    print("[Server] Waiting for encrypted credentials...")
    encrypted_data = protocol.receive_message(conn)
    if not encrypted_data:
        raise Exception("Client disconnected before sending credentials.")

    # 1. Decrypt the message
    try:
        decrypted_json_bytes = aes.decrypt(temp_aes_key, encrypted_data)
        data = json.loads(decrypted_json_bytes.decode('utf-8'))
        print(f"[Server] Decrypted data: {data}")
    except Exception as e:
        print(f"[Server] Failed to decrypt/parse credentials: {e}")
        err_msg = protocol.StatusMessage(success=False, message="Decryption failed")
        encrypted_response = aes.encrypt(temp_aes_key, err_msg.model_dump_json().encode('utf-8'))
        protocol.send_message(conn, encrypted_response)
        return None

    # 2. Process the message
    username = data.get('username') # Get username for return
    try:
        if data.get('type') == 'register':
            model = protocol.SecureRegister(**data)
            db.register_user(model.email, model.username, model.password)
            response = protocol.StatusMessage(
                success=True, 
                message=f"User {model.username} registered successfully."
            )
        elif data.get('type') == 'login':
            model = protocol.SecureLogin(**data)
            login_ok = db.verify_login(model.username, model.password)
            
            if login_ok:
                response = protocol.StatusMessage(
                    success=True,
                    message=f"User {model.username} logged in successfully."
                )
                
                # Send login success *before* Phase 3
                encrypted_response = aes.encrypt(temp_aes_key, response.model_dump_json().encode('utf-8'))
                protocol.send_message(conn, encrypted_response)
                print(f"[Server] Sent encrypted status response (login OK).")
                
                # --- SUCCESS: Return username ---
                return model.username 
            else:
                response = protocol.StatusMessage(
                    success=False,
                    message="Login failed: Invalid username or password."
                )
        else:
            raise Exception("Invalid message type received.")
            
    except Exception as e:
        print(f"[Server] Error processing credentials: {e}")
        response = protocol.StatusMessage(success=False, message=str(e))

    # 5. Send encrypted response (for register or failed login)
    encrypted_response = aes.encrypt(temp_aes_key, response.model_dump_json().encode('utf-8'))
    protocol.send_message(conn, encrypted_response)
    print(f"[Server] Sent encrypted status response.")
    return None # No successful login

def handle_temp_dh_exchange(conn: socket.socket) -> bytes:
    """
    Performs the temporary DH exchange (Req 2.2.3).
    Returns the 16-byte temporary AES key.
    """
    print("[Server] Starting temporary DH exchange...")
    
    # 1. Receive client DH hello
    client_hello_data = protocol.receive_json_message(conn)
    if not client_hello_data:
        raise Exception("Client disconnected during DH.")
    
    # using renamed model
    client_hello = protocol.TempDHClientHello(**client_hello_data) # <-- RENAMED
    
    # 2. Generate server key and shared secret
    B_y, shared_secret_Ks = dh.get_server_dh_secret(
        client_hello.p, client_hello.g, client_hello.A_y
    )
    
    # 3. Send server DH hello
    # using renamed model
    server_hello = protocol.TempDHServerReply(B_y=B_y) # <-- RENAMED
    protocol.send_json_message(conn, server_hello)
    
    # 4. Derive AES key (K = Trunc16(SHA256(Ks)))
    temp_aes_key = dh.derive_aes_key(shared_secret_Ks)
    print("[Server] Temporary AES key derived.")
    return temp_aes_key

def handle_session_key_exchange(conn: socket.socket) -> bytes:
    """
    Performs the FINAL session key DH exchange (Req 2.3).
    Returns the 16-byte FINAL session AES key.
    """
    print("[Server] Starting FINAL session key DH exchange...")
    
    # 1. Receive client DH hello (using the new model)
    client_msg_data = protocol.receive_json_message(conn)
    if not client_msg_data:
        raise Exception("Client disconnected during session DH.")
    
    client_msg = protocol.DHClient(**client_msg_data)
    
    # 2. Generate server key and shared secret
    B_y, shared_secret_Ks = dh.get_server_dh_secret(
        client_msg.p, client_msg.g, client_msg.A_y
    )
    
    # 3. Send server DH reply (using the new model)
    server_reply = protocol.DHServer(B_y=B_y)
    protocol.send_json_message(conn, server_reply)
    
    # 4. Derive FINAL AES key (K = Trunc16(SHA256(Ks)))
    session_aes_key = dh.derive_aes_key(shared_secret_Ks)
    print("[Server] FINAL Session AES key derived.")
    return session_aes_key

def handle_client(conn: socket.socket):
    """
    Handles a single client connection, from auth to login to chat.
    """
    temp_aes_key = None
    session_key = None
    client_username = None
    
    try:
        print(f"\n[Server] New client connected from {conn.getpeername()}.")
        
        # 1. Load all server certs/keys
        ca_cert = pki.load_ca_cert()
        server_cert = pki.load_certificate("server.crt")
        server_key = pki.load_private_key("server.key")
        
        # --- PHASE 2A: Mutual Authentication (Req 2.1) ---
        # 1. SERVER SENDS FIRST
        print("[Server] Sending server certificate...")
        protocol.send_message(conn, pki.serialize_cert(server_cert))

        # 2. SERVER RECEIVES SECOND
        print("[Server] Waiting for client certificate...")
        client_cert_pem = protocol.receive_message(conn)
        
        if not client_cert_pem:
            return # Client disconnected

        client_cert = pki.deserialize_cert(client_cert_pem)
        pki.validate_certificate(client_cert, ca_cert, expected_cn="client")
        print("\n[Server] Mutual Authentication Successful!")
        
        auth_success_msg = protocol.AuthSuccessMessage(message="Mutual auth OK. Ready for DH.")
        protocol.send_json_message(conn, auth_success_msg)

        # --- PHASE 2B: Secure Credentials (Req 2.2) ---
        temp_aes_key = handle_temp_dh_exchange(conn)
        
        # Add a small delay to prevent a race condition
        time.sleep(0.1) 
        
        # This function now returns the client's username on success
        client_username = handle_secure_credentials(conn, temp_aes_key)
        
        # --- PHASE 3: Session Key (Req 2.3) ---
        if client_username: # Only if login was successful
            session_key = handle_session_key_exchange(conn)
            
            # --- PHASE 4: Chat (Req 2.4) ---
            print(f"[Server] Starting chat session for {client_username}...")
            
            # 1. Initialize transcript
            server_transcript = transcript.Transcript(
                username=client_username,
                role="server"
            )
            
            # 2. Initialize chat session
            chat_session = chat.ChatSession(
                sock=conn,
                session_key=session_key,
                my_username="server", # Server is just "server"
                my_private_key=server_key,
                peer_username=client_username,
                peer_certificate=client_cert,
                transcript=server_transcript
            )
            
            # 3. Start chat (this blocks until chat ends)
            chat_session.start()

    except Exception as e:
        print(f"[Server] Error handling client: {e}")
        if temp_aes_key and not session_key and not conn._closed:
             try:
                err_msg = protocol.StatusMessage(success=False, message=str(e))
                encrypted_response = aes.encrypt(temp_aes_key, err_msg.model_dump_json().encode('utf-8'))
                protocol.send_message(conn, encrypted_response)
             except Exception as e_inner:
                print(f"[Server] Failed to send final error: {e_inner}")
        
    finally:
        print(f"[Server] Closing client connection for {client_username or 'peer'}.")
        conn.close()

def main():
    """Server main loop."""
    HOST = 'localhost' 
    PORT = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"Secure Chat Server listening on {HOST}:{PORT}...")
        
        while True:
            try:
                conn, addr = s.accept()
                handle_client(conn) 
            except KeyboardInterrupt:
                print("\n[Server] Shutting down...")
                break
            except Exception as e:
                print(f"[Server] Error in accept loop: {e}")

if __name__ == "__main__":
    main()