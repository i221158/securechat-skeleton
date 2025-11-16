"""
Server main logic.
Handles mutual auth, temporary DH, and secure credential processing.
"""

import socket
import json
from .common import protocol
from .crypto import pki, dh, aes
from .storage import db

def handle_secure_credentials(conn: socket.socket, temp_aes_key: bytes):
    """
    Handles the encrypted registration or login message (Req 2.2.4).
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
        # Send encrypted error response
        err_msg = protocol.StatusMessage(success=False, message="Decryption failed")
        encrypted_response = aes.encrypt(temp_aes_key, err_msg.model_dump_json().encode('utf-8'))
        protocol.send_message(conn, encrypted_response)
        return

    # 2. Process the message
    try:
        if data.get('type') == 'register':
            # 3. Handle Registration (Req 2.2.5)
            model = protocol.SecureRegister(**data)
            db.register_user(model.email, model.username, model.password)
            response = protocol.StatusMessage(
                success=True, 
                message=f"User {model.username} registered successfully."
            )
        elif data.get('type') == 'login':
            # 4. Handle Login (Req 2.2.6)
            model = protocol.SecureLogin(**data)
            login_ok = db.verify_login(model.username, model.password)
            
            if login_ok:
                response = protocol.StatusMessage(
                    success=True,
                    message=f"User {model.username} logged in successfully."
                )
                # TODO: Phase 3 (Session Key) will start here
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

    # 5. Send encrypted response (Req 2.2.7)
    encrypted_response = aes.encrypt(temp_aes_key, response.model_dump_json().encode('utf-8'))
    protocol.send_message(conn, encrypted_response)
    print(f"[Server] Sent encrypted status response.")


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
    
    client_hello = protocol.DHClientHello(**client_hello_data)
    
    # 2. Generate server key and shared secret
    B_y, shared_secret_Ks = dh.get_server_dh_secret(
        client_hello.p, client_hello.g, client_hello.A_y
    )
    
    # 3. Send server DH hello
    server_hello = protocol.DHServerHello(B_y=B_y)
    protocol.send_json_message(conn, server_hello)
    
    # 4. Derive AES key (K = Trunc16(SHA256(Ks)))
    temp_aes_key = dh.derive_aes_key(shared_secret_Ks)
    print("[Server] Temporary AES key derived.")
    return temp_aes_key


def handle_client(conn: socket.socket):
    """
    Handles a single client connection, from auth to login.
    """
    temp_aes_key = None
    try:
        print(f"\n[Server] New client connected from {conn.getpeername()}.")
        
        # --- PHASE 2A: Mutual Authentication (Req 2.1) ---
        ca_cert = pki.load_ca_cert()
        server_cert = pki.load_certificate("server.crt")
        
        print("[Server] Sending server certificate...")
        protocol.send_message(conn, pki.serialize_cert(server_cert))

        print("[Server] Waiting for client certificate...")
        client_cert_pem = protocol.receive_message(conn)
        if not client_cert_pem:
            print("[Server] Client disconnected.")
            return

        client_cert = pki.deserialize_cert(client_cert_pem)
        pki.validate_certificate(client_cert, ca_cert, expected_cn="client")
        print("\n[Server] Mutual Authentication Successful!")
        
        # Send auth success message to signal next phase
        auth_success_msg = protocol.AuthSuccessMessage(
            message="Mutual auth OK. Ready for DH."
        )
        protocol.send_json_message(conn, auth_success_msg)

        # --- PHASE 2B: Secure Credentials (Req 2.2) ---
        
        # 1. Perform temporary DH exchange
        temp_aes_key = handle_temp_dh_exchange(conn)
        
        # 2. Handle encrypted registration/login
        handle_secure_credentials(conn, temp_aes_key)
        
        # --- PHASE 3: Session Key (Req 2.3) ---
        # TODO: This will be implemented next.
        

    except Exception as e:
        print(f"[Server] Error handling client: {e}")
        # If we have an AES key, try to send an encrypted error
        if temp_aes_key and not conn._closed:
            try:
                err_msg = protocol.StatusMessage(success=False, message=str(e))
                encrypted_response = aes.encrypt(temp_aes_key, err_msg.model_dump_json().encode('utf-8'))
                protocol.send_message(conn, encrypted_response)
            except Exception as e_inner:
                print(f"[Server] Failed to send final error: {e_inner}")
        
    finally:
        print("[Server] Closing client connection.")
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