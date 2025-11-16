"""
X.509 validation: signed-by-CA, validity window, CN/SAN.
Also includes helper functions for loading certs and keys.
"""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# --- File Loading ---

CERTS_DIR = "certs"
CA_CERT_FILE = os.path.join(CERTS_DIR, "ca.crt")

def load_ca_cert():
    """Loads the CA's public certificate."""
    try:
        with open(CA_CERT_FILE, "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())
    except FileNotFoundError:
        print(f"Error: CA certificate not found at {CA_CERT_FILE}")
        print("Please run 'python scripts/gen_ca.py' first.")
        exit(1)

def load_private_key(key_file_name):
    """Loads a private key (e.g., server.key or client.key)."""
    path = os.path.join(CERTS_DIR, key_file_name)
    try:
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
    except FileNotFoundError:
        print(f"Error: Private key {path} not found.")
        print("Please run 'python scripts/gen_cert.py' first.")
        exit(1)

def load_certificate(cert_file_name):
    """Loads a public certificate (e.g., server.crt or client.crt)."""
    path = os.path.join(CERTS_DIR, cert_file_name)
    try:
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())
    except FileNotFoundError:
        print(f"Error: Certificate {path} not found.")
        print("Please run 'python scripts/gen_cert.py' first.")
        exit(1)

# --- Certificate Serialization ---

def serialize_cert(cert):
    """Converts a certificate object to PEM bytes to send over the network."""
    return cert.public_bytes(serialization.Encoding.PEM)

def deserialize_cert(pem_data):
    """Converts PEM bytes received from the network back into a certificate object."""
    return x509.load_pem_x509_certificate(pem_data, default_backend())

# --- Certificate Validation (Requirement 2.1.v) ---

def validate_certificate(cert_to_validate: x509.Certificate, ca_cert: x509.Certificate, expected_cn: str):
    """
    Validates a received certificate against the assignment criteria.
    [cite: 162, 163, 164, 165]
    """
    print(f"Validating certificate for CN: {expected_cn}...")

    # 1. Check signature chain validity (Req 2.1.v.i) [cite: 163]
    ca_public_key = ca_cert.public_key()
    try:
        ca_public_key.verify(
            cert_to_validate.signature,
            cert_to_validate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert_to_validate.signature_hash_algorithm,
        )
        print("  Signature is valid (signed by our CA).")
    except InvalidSignature:
        print("  Signature is INVALID. (Not signed by our CA)")
        raise Exception("BAD_CERT: Invalid signature")

    # 2. Check expiry date and validity period (Req 2.1.v.ii) [cite: 164]
    now = datetime.datetime.utcnow()
    if now < cert_to_validate.not_valid_before:
        print("  Certificate is not yet valid.")
        raise Exception("BAD_CERT: Certificate not yet valid")
    if now > cert_to_validate.not_valid_after:
        print("  Certificate has expired.")
        raise Exception("BAD_CERT: Certificate expired")
    
    print(f"  Certificate is within its validity period.")

    # 3. Check Common Name (CN) match (Req 2.1.v.iii) [cite: 165]
    subject = cert_to_validate.subject
    cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    
    if cn != expected_cn:
        print(f"  Common Name mismatch. Expected '{expected_cn}', got '{cn}'.")
        raise Exception(f"BAD_CERT: Common Name mismatch. Expected {expected_cn}")
    
    print(f"  Common Name matches ('{cn}').")
    print(f"Certificate for {expected_cn} is valid.\n")
    return True