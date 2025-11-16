"""
Append-only transcript + TranscriptHash helpers.
Implements logging for Requirement 2.5.
"""

import os
import hashlib
from . import db # We'll reuse the DB's dir for logs, or make a new one
from ..common import utils
from ..crypto import sign
from cryptography.hazmat.primitives import rsa, serialization
from cryptography import x509

# Define where logs are stored
LOGS_DIR = "logs"

class Transcript:
    def __init__(self, username: str, role: str):
        """
        Initializes and opens an append-only transcript file.
        
        Args:
            username: The name of the user for this session.
            role: 'client' or 'server', to prevent filename collision.
        """
        os.makedirs(LOGS_DIR, exist_ok=True)
        
        # Create a unique, predictable filename
        timestamp = utils.now_ms() // 1000 # Get seconds
        self.filename = os.path.join(
            LOGS_DIR, 
            f"transcript_{role}_{username}_{timestamp}.log"
        )
        
        # Open the file in 'append' mode. 'a+' creates it if not exists.
        try:
            # We open/close on each write to ensure data is flushed,
            # which is safer for this assignment.
            # For a real app, we'd keep it open.
            self.file_handle = open(self.filename, 'a+', encoding='utf-8')
            print(f"[Transcript] Logging session to {self.filename}")
        except Exception as e:
            print(f"FATAL: Could not open transcript file: {e}")
            raise
        
        # We'll just keep the handle open
        self.all_lines_for_hash = [] # Keep lines in memory for final hash

    def append(self, seqno: int, ts: int, ct_b64: str, sig_b64: str, peer_cert_fp_hex: str):
        """
        Appends a fully formatted log line to the transcript.
        Format: seqno | ts | ct | sig | peer-cert-fingerprint
        """
        try:
            # 1. Create the log line
            # (Req 2.5.i)
            log_line = f"{seqno} | {ts} | {ct_b64} | {sig_b64} | {peer_cert_fp_hex}\n"
            
            # 2. Write to file and flush
            self.file_handle.write(log_line)
            self.file_handle.flush()
            
            # 3. Store in memory for final hash
            self.all_lines_for_hash.append(log_line)
            
        except Exception as e:
            print(f"Error writing to transcript: {e}")

    def get_transcript_hash(self) -> bytes:
        """
        Computes the final TranscriptHash.
        H = SHA256(concatenation of all log lines)
        (Req 2.5.ii)
        """
        # 1. Concatenate all lines in order
        full_transcript = "".join(self.all_lines_for_hash)
        
        # 2. Compute SHA-256 hash
        return utils.sha256_bytes(full_transcript.encode('utf-8'))

    def generate_receipt(self, private_key: rsa.RSAPrivateKey) -> str:
        """
        Generates the final signed SessionReceipt.
        Computes the hash, then signs it.
        (Req 2.5.ii)
        
        Returns:
            The Base64-encoded signature of the TranscriptHash.
        """
        print("[Transcript] Generating session receipt...")
        # 1. Get the final hash
        transcript_hash_bytes = self.get_transcript_hash()
        
        # 2. Sign the hash
        signature = sign.sign(private_key, transcript_hash_bytes)
        
        # 3. Return the Base64-encoded signature
        return utils.b64e(signature)

    def close(self):
        """Closes the file handle."""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None