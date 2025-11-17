"""
Client main logic.
Handles mutual auth, temp DH, and secure credential submission.
"""

import socket
import json
from typing import Union
import getpass
from .common import protocol
from .crypto import pki, dh, aes
from .storage import transcript
from . import chat

def perform_temp_dh_exchange(sock: socket.socket) -> bytes:
    """
    Performs the temporary DH exchange (Req 2.2.3).
    Returns the 16-byte temporary AES key.
    """
    print("[Client] Starting temporary DH exchange...")
    
    # 1. Generate client DH values
    client_priv_key, p, g, A_y = dh.generate_client_dh()
    
    # 2. Send client DH hello
    # USE RENAMED MODEL
    client_hello = protocol.TempDHClientHello(p=p, g=g, A_y=A_y) # <-- RENAMED
    protocol.send_json_message(sock, client_hello)
    
    # 3. Receive server DH hello
    server_hello_data = protocol.receive_json_message(sock)
    if not server_hello_data:
        raise Exception("Server disconnected during DH.")
    
    # USE RENAMED MODEL
    server_hello = protocol.TempDHServerReply(**server_hello_data) # <-- RENAMED
    
    # 4. Compute shared secret
    shared_secret_Ks = dh.get_client_dh_shared_secret(
        p, g, server_hello.B_y, client_priv_key
    )
    
    # 5. Derive AES key (K = Trunc16(SHA256(Ks)))
    temp_aes_key = dh.derive_aes_key(shared_secret_Ks)
    print("[Client] Temporary AES key derived.")
    return temp_aes_key

def perform_session_key_exchange(sock: socket.socket) -> bytes:
    """
    Performs the FINAL session key DH exchange (Req 2.3).
    Returns the 16-byte FINAL session AES key.
    """
    print("[Client] Starting FINAL session key DH exchange...")
    
    # 1. Generate client DH values
    client_priv_key, p, g, A_y = dh.generate_client_dh()
    
    # 2. Send client DH hello (using the new model)
    client_msg = protocol.DHClient(p=p, g=g, A_y=A_y) 
    protocol.send_json_message(sock, client_msg)
    
    # 3. Receive server DH reply (using the new model)
    server_reply_data = protocol.receive_json_message(sock)
    if not server_reply_data:
        raise Exception("Server disconnected during session DH.")
    
    server_reply = protocol.DHServer(**server_reply_data)
    
    # 4. Compute shared secret
    shared_secret_Ks = dh.get_client_dh_shared_secret(
        p, g, server_reply.B_y, client_priv_key
    )
    
    # 5. Derive FINAL AES key (K = Trunc16(SHA256(Ks)))
    session_aes_key = dh.derive_aes_key(shared_secret_Ks) 
    print("[Client] FINAL Session AES key derived.")
    return session_aes_key

def main():
    """Client main logic."""
    HOST = 'localhost' 
    PORT = 12345       
    temp_aes_key = None
    action = "" 
    username = "" # Define username in outer scope

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"[Client] Connecting to {HOST}:{PORT}...")
            s.connect((HOST, PORT))
            print("[Client] Connected.")

            # --- PHASE 2A: Mutual Authentication (Req 2.1) ---
            ca_cert = pki.load_ca_cert()
            client_cert = pki.load_certificate("client.crt")
            client_key = pki.load_private_key("client.key") # key load
            
            print("[Client] Waiting for server certificate...")
            server_cert_pem = protocol.receive_message(s)
            if not server_cert_pem:
                raise Exception("Server closed connection.")

            server_cert = pki.deserialize_cert(server_cert_pem)
            pki.validate_certificate(server_cert, ca_cert, expected_cn="localhost")
            print("[Client] Server certificate is valid.")

            print("[Client] Sending client certificate...")
            protocol.send_message(s, pki.serialize_cert(client_cert))

            print("\n[Client]  Mutual Authentication Successful!")
            
            auth_response = protocol.receive_json_message(s)
            if not auth_response or auth_response.get('status') != 'auth_success':
                raise Exception("Server did not acknowledge mutual auth.")
            print(f"[Client] Server says: {auth_response.get('message')}")
            
            # --- PHASE 2B: Secure Credentials (Req 2.2) ---
            temp_aes_key = perform_temp_dh_exchange(s)
            
            while action not in ['r', 'l']:
                action = input("Do you want to (r)egister or (l)ogin? ").strip().lower()

            username = input("Enter username: ").strip()
            password = getpass.getpass("Enter password: ")
            
            if action == 'r':
                email = input("Enter email: ").strip()
                model = protocol.SecureRegister(
                    email=email, username=username, password=password
                )
            else: # action == 'l'
                model = protocol.SecureLogin(
                    username=username, password=password
                )

            print(f"[Client] Encrypting and sending {model.type} request...")
            json_bytes = model.model_dump_json().encode('utf-8')
            encrypted_request = aes.encrypt(temp_aes_key, json_bytes)
            protocol.send_message(s, encrypted_request)
            
            encrypted_response = protocol.receive_message(s)
            if not encrypted_response:
                raise Exception("Server closed connection before sending status.")
            
            decrypted_response_bytes = aes.decrypt(temp_aes_key, encrypted_response)
            status_data = json.loads(decrypted_response_bytes.decode('utf-8'))
            response = protocol.StatusMessage(**status_data)
            
            # --- Check Response and Start Phase 3/4 ---
            if response.success:
                print(f"[Client] _/ Success: {response.message}")
                
                if action == 'l':
                    # --- PHASE 3: Session Key (Req 2.3) ---
                    session_key = perform_session_key_exchange(s)
                    
                    # --- PHASE 4: Chat (Req 2.4) ---
                    print(f"[Client] Starting chat session as {username}...")
                    
                    # 1. Initialize transcript
                    client_transcript = transcript.Transcript(
                        username=username,
                        role="client"
                    )
                    
                    # 2. Initialize chat session
                    chat_session = chat.ChatSession(
                        sock=s,
                        session_key=session_key,
                        my_username=username,
                        my_private_key=client_key,
                        peer_username="server",
                        peer_certificate=server_cert,
                        transcript=client_transcript,
                        is_client=True # To print the prompt
                    )
                    
                    # 3. Start chat (this blocks until chat ends)
                    chat_session.start()

            else:
                print(f"[Client] X Failure: {response.message}")

    except ConnectionRefusedError:
        print(f"[Client] Error: Connection refused. Is the server running?")
    except Exception as e:
        print(f"[Client] An error occurred: {e}")
        # (Rest of exception handling is unchanged)

if __name__ == "__main__":
    main()