#made this file so that it handle the complex, multi-threaded logic of sending and receiving messages at the same time.

"""
Implements the main, threaded, encrypted chat loop (Req 2.4 & 2.5).
"""
import socket
import sys
import threading
import json
import queue # For thread-safe message passing
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from .common import protocol, utils
from .crypto import aes, sign
from .storage import transcript

class ChatSession:
    """
    Manages a live, encrypted chat session, including sending,
    receiving, signing, verifying, and logging.
    """
    def __init__(self, 
                 sock: socket.socket, 
                 session_key: bytes, 
                 my_username: str,
                 my_private_key: rsa.RSAPrivateKey, 
                 peer_username: str,
                 peer_certificate: x509.Certificate,
                 transcript: transcript.Transcript,
                 is_client: bool = False):
        
        self.sock = sock
        self.session_key = session_key
        self.my_username = my_username
        self.my_private_key = my_private_key
        self.peer_username = peer_username
        self.peer_certificate = peer_certificate
        self.transcript = transcript
        self.is_client = is_client # Client prints prompt, server doesn't

        # Get peer cert fingerprint for logging (Req 2.5.i)
        # We'll use SHA-256 hash of the cert's raw bytes (DER format)
        self.peer_cert_fp_hex = utils.sha256_hex(
            self.peer_certificate.public_bytes(
                encoding=serialization.Encoding.DER
            )
        )
        
        # --- State for CIANR (Req 2.4.ii, 2.4.iv) ---
        self.send_seqno = 0
        self.recv_seqno = -1 # Start at -1, so first msg (0) is >
        self.send_lock = threading.Lock() # Lock for send_seqno
        
        self.stop_event = threading.Event() # To signal threads to stop
        self.message_queue = queue.Queue() # For received messages
        
        print("\n--- Secure Chat Session Started ---")
        print(f"Logged in as {my_username}. Chatting with {peer_username}.")
        print('Type your message and press Enter. Type "quit" to exit.')

    def _prepare_message(self, plaintext: str) -> protocol.ChatMessage:
        """
        Encrypts, signs, and packages a plaintext message.
        (Req 2.4.i, 2.4.ii)
        """
        with self.send_lock:
            # 1. Get sequence number and timestamp
            seqno = self.send_seqno
            self.send_seqno += 1
            ts = utils.now_ms()
            
            # 2. Encrypt plaintext (AES-128)
            ciphertext_bytes = aes.encrypt(self.session_key, plaintext.encode('utf-8'))
            ct_b64 = utils.b64e(ciphertext_bytes)
            
            # 3. Create hash: h = SHA256(seqno || ts || ct)
            # We must use the *bytes* of the Base64 ciphertext
            hash_data = f"{seqno}{ts}{ct_b64}".encode('utf-8')
            data_hash_bytes = utils.sha256_bytes(hash_data)
            
            # 4. Sign the hash (RSA)
            signature_bytes = sign.sign(self.my_private_key, data_hash_bytes)
            sig_b64 = utils.b64e(signature_bytes)
            
            # 5. Log to transcript *before* sending
            self.transcript.append(seqno, ts, ct_b64, sig_b64, self.peer_cert_fp_hex)
            
            # 6. Create message model
            return protocol.ChatMessage(
                seqno=seqno,
                ts=ts,
                ct=ct_b64,
                sig=sig_b64
            )

    def _verify_message(self, msg: protocol.ChatMessage):
        """
        Verifies, decrypts, and unpackages a received message.
        (Req 2.4.iii, 2.4.iv)
        Returns the plaintext string.
        """
        # 1. Check for replay attack (Req 2.4.iv)
        if msg.seqno <= self.recv_seqno:
            raise Exception(f"REPLAY ATTACK DETECTED. "
                            f"Got seqno {msg.seqno}, but expected > {self.recv_seqno}")
        
        # 2. Verify signature (Req 2.4.iii)
        # Re-create hash: h' = SHA256(seqno || ts || ct)
        hash_data = f"{msg.seqno}{msg.ts}{msg.ct}".encode('utf-8')
        data_hash_bytes = utils.sha256_bytes(hash_data)
        
        # Decode signature
        signature_bytes = utils.b64d(msg.sig)
        
        if not sign.verify(self.peer_certificate, signature_bytes, data_hash_bytes):
            raise Exception("SIGNATURE VERIFICATION FAILED (SIG_FAIL). Message tampered.")
            
        # 3. Log to transcript *after* verifying
        self.transcript.append(
            msg.seqno, msg.ts, msg.ct, msg.sig, self.peer_cert_fp_hex
        )
        
        # 4. Update sequence number
        self.recv_seqno = msg.seqno
        
        # 5. Decrypt message
        ciphertext_bytes = utils.b64d(msg.ct)
        plaintext_bytes = aes.decrypt(self.session_key, ciphertext_bytes)
        
        return plaintext_bytes.decode('utf-8')

    def _network_listen_thread(self):
        """
        Thread target. Listens for messages on the socket.
        Handles message verification and receipt exchange.
        """
        print("[Chat] Network listener started...")
        while not self.stop_event.is_set():
            try:
                # Use a timeout so the loop can check stop_event
                self.sock.settimeout(1.0)
                json_data = protocol.receive_json_message(self.sock)
                self.sock.settimeout(None) # Reset timeout
                
                if json_data is None:
                    print("[Chat] Peer disconnected.")
                    self.stop_event.set()
                    break
                
                msg_type = json_data.get('type')
                
                if msg_type == 'msg':
                    # --- Process a Chat Message ---
                    msg = protocol.ChatMessage(**json_data)
                    plaintext = self._verify_message(msg)
                    print(f"\r[{self.peer_username}] {plaintext}")
                    if self.is_client:
                        print(f"[{self.my_username}]> ", end="", flush=True)

                elif msg_type == 'receipt':
                    # --- Process a Session Receipt (Req 2.5.ii) ---
                    print("[Chat] Received final session receipt from peer.")
                    receipt_msg = protocol.SessionReceiptMessage(**json_data)
                    print(f"\n--- PEER RECEIPT (for verifier) ---\n{receipt_msg.sig}\n")
                    self.stop_event.set()
            except socket.timeout:
                continue # Loop back to check stop_event
            except Exception as e:
                print(f"\r[Chat Error] {e}")
                self.stop_event.set()
        print("[Chat] Network listener stopped.")

    def _user_input_thread(self):
        """
        Thread target. Listens for user input from stdin.
        """
        print("[Chat] User input listener started...")
        while not self.stop_event.is_set():
            try:
                if not self.is_client:
                    threading.Event().wait(1.0) # Sleep for 1 sec
                    continue
                print(f"[{self.my_username}]> ", end="", flush=True)
                # This is a blocking call, but we can't easily
                # make stdin non-blocking. We'll rely on the
                # network thread to set the stop_event.
                plaintext = input()
                
                if self.stop_event.is_set():
                    break
                
                if plaintext.lower() == 'quit':
                    print("[Chat] Quitting...")
                    self.stop_event.set()
                    break

                if not plaintext:
                    continue

                # 1. Prepare and send message
                chat_msg = self._prepare_message(plaintext)
                protocol.send_json_message(self.sock, chat_msg)

            except EOFError: # User pressed Ctrl+D
                print("[Chat] EOF received. Quitting...")
                self.stop_event.set()
            except Exception as e:
                if not self.stop_event.is_set():
                    print(f"\r[Input Error] {e}")
                    self.stop_event.set()
        
        print("[Chat] User input listener stopped.")

    def start(self):
        """
        Starts the chat session by launching threads.
        Blocks until the session ends.
        """
        # Start the network listener thread
        net_thread = threading.Thread(target=self._network_listen_thread, daemon=True)
        net_thread.start()
        
        # Start the user input listener thread
        input_thread = threading.Thread(target=self._user_input_thread, daemon=True)
        input_thread.start()

        # Wait here until one of the threads sets the stop_event
        try:
            while not self.stop_event.is_set():
                threading.Event().wait(0.5) # Just wait
        except KeyboardInterrupt: # User pressed Ctrl+C
            print("\n[Chat] Ctrl+C received. Quitting...")
            self.stop_event.set()

        # --- Graceful Shutdown (Req 2.5.ii) ---
        print("[Chat] Shutting down and exchanging receipts...")
        
        # 1. Generate our receipt
        my_receipt_sig = self.transcript.generate_receipt(self.my_private_key)
        receipt_msg = protocol.SessionReceiptMessage(sig=my_receipt_sig)
        
        # 2. Send our receipt
        try:
            protocol.send_json_message(self.sock, receipt_msg)
            print("[Chat] Sent final session receipt.")
        except Exception as e:
            print(f"[Chat] Could not send final receipt: {e}")
            
        # 3. Wait for threads to finish
        net_thread.join(timeout=2.0)
        input_thread.join(timeout=2.0)
        
        # 4. Close transcript
        self.transcript.close()
        
        print("--- Secure Chat Session Ended ---")