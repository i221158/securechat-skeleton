"""
Offline Transcript Verification Script (Req 2.5.ii)

This script reads a chat transcript log, loads the peer's
certificate, and verifies a provided SessionReceipt signature
against the transcript's computed hash.

Usage:
    python verify_transcript.py
"""

import sys
import os
import hashlib
import base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric import utils as crypto_utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# --- Helper Functions (copied from project) ---

def load_certificate(cert_file_name: str, certs_dir: str = "certs"):
    """Loads a public certificate from the certs directory."""
    path = os.path.join(certs_dir, cert_file_name)
    try:
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())
    except FileNotFoundError:
        print(f"Error: Certificate {path} not found.")
        exit(1)

def sha256_bytes(data: bytes) -> bytes:
    """Computes the SHA-256 hash and returns raw bytes."""
    return hashlib.sha256(data).digest()

def b64d(s: str) -> bytes:
    """Decodes a URL-safe Base64-encoded string."""
    try:
        return base64.urlsafe_b64decode(s.encode('utf-8'))
    except (base64.binascii.Error, ValueError) as e:
        raise ValueError(f"Invalid Base64 string: {e}") from e

def verify_signature(certificate: x509.Certificate, signature: bytes, data_hash: bytes) -> bool:
    """
    Verifies an RSA-PKCS#1 v1.5 signature against a pre-computed SHA-256 digest.
    """
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        return False
        
    try:
        public_key.verify(
            signature,
            data_hash,
            padding.PKCS1v15(),
            crypto_utils.Prehashed(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False

def compute_transcript_hash(log_file_path: str) -> bytes:
    """
    Reads all lines from a log file and computes the final TranscriptHash.
    """
    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        sys.exit(1)
        
    if not all_lines:
        print(f"Error: Log file {log_file_path} is empty.")
        sys.exit(1)
        
    print(f"Read {len(all_lines)} lines from transcript.")
    
    full_transcript = "".join(all_lines)
    hash_bytes = sha256_bytes(full_transcript.encode('utf-8'))
    return hash_bytes

# --- Main Verifier Logic ---

def main():
    print("\n--- SecureChat Offline Transcript Verifier ---")
    
    # 1. Get user inputs
    try:
        log_file = input("Enter path to the LOG file (e.g., logs/transcript_client_...log): ").strip()
        peer_cert_file = input("Enter path to the PEER'S cert (e.g., certs/server.crt): ").strip()
        peer_receipt_sig_b64 = input("Paste the PEER'S receipt signature (from their console): ").strip()
    except EOFError:
        sys.exit(1)
        
    # 2. Load the peer's certificate
    peer_cert = load_certificate(os.path.basename(peer_cert_file))
    print(f"Loaded peer certificate: {peer_cert_file}")
    
    # 3. Decode the signature
    try:
        peer_receipt_sig_bytes = b64d(peer_receipt_sig_b64)
    except Exception as e:
        print(f"Error: Invalid Base64 signature. {e}")
        sys.exit(1)

    # 4. Compute the hash of the *local* transcript
    local_transcript_hash_bytes = compute_transcript_hash(log_file)
    print(f"Computed local transcript hash: {local_transcript_hash_bytes.hex()}")
    
    # 5. Verify the peer's signature against our local hash
    print("Verifying peer's signature against local transcript hash...")
    
    is_valid = verify_signature(
        certificate=peer_cert,
        signature=peer_receipt_sig_bytes,
        data_hash=local_transcript_hash_bytes
    )
    
    if is_valid:
        print("\n--- SUCCESS ---")
        print("Verification successful. The peer's receipt matches this transcript.")
    else:
        print("\n--- FAILURE ---")
        print("Verification FAILED. The peer's receipt does NOT match this transcript.")

if __name__ == "__main__":
    main()