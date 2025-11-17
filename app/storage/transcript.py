"""
Append-only transcript + TranscriptHash helpers.
Implements logging for Requirement 2.5.
"""

import os
import hashlib
from . import db 
from ..common import utils
from ..crypto import sign
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509

# Define where logs are stored
LOGS_DIR = "logs"

class Transcript:
    def __init__(self, username: str, role: str):
        os.makedirs(LOGS_DIR, exist_ok=True)
        timestamp = utils.now_ms() // 1000 
        self.filename = os.path.join(
            LOGS_DIR, 
            f"transcript_{role}_{username}_{timestamp}.log"
        )
        print(f"[Transcript] Logging session to {self.filename}")
        self.all_lines_for_hash = [] 

    def append(self, seqno: int, ts: int, ct_b64: str, sig_b64: str, peer_cert_fp_hex: str):
        """
        Appends a fully formatted log line to the transcript.
        """
        try:
            # 1. Create the log line
            log_line = f"{seqno} | {ts} | {ct_b64} | {sig_b64} | {peer_cert_fp_hex}\n"
            
            # 2. Open, write, and close/flush the file.
            #    This 'with' block is the critical fix.
            with open(self.filename, 'a+', encoding='utf-8') as f:
                f.write(log_line)
            
            # 3. Store in memory
            self.all_lines_for_hash.append(log_line)
            
        except Exception as e:
            print(f"Error writing to transcript: {e}")

    def get_transcript_hash(self) -> bytes:
        """
        Computes the final TranscriptHash.
        """
        full_transcript = "".join(self.all_lines_for_hash)
        return utils.sha256_bytes(full_transcript.encode('utf-8'))

    def generate_receipt(self, private_key: rsa.RSAPrivateKey) -> str:
        """
        Generates the final signed SessionReceipt.
        """
        print("[Transcript] Generating session receipt...")
        transcript_hash_bytes = self.get_transcript_hash()
        signature = sign.sign(private_key, transcript_hash_bytes)
        return utils.b64e(signature)

    def close(self):
        """No file handle is kept open, so nothing to do."""
        pass