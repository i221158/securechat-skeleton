"""
Create Root CA (RSA + self-signed X.509) using cryptography.
This script generates the CA's private key and self-signed certificate.
"""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Define constants
CERTS_DIR = "certs"
CA_KEY_FILE = os.path.join(CERTS_DIR, "ca.key")
CA_CERT_FILE = os.path.join(CERTS_DIR, "ca.crt")

def generate_ca():
    print(f"Generating CA key and certificate...")
    
    # 1. Ensure the certs directory exists
    os.makedirs(CERTS_DIR, exist_ok=True)

    # 2. Generate a new RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 3. Write the private key to a file (in PEM format)
    # This key must be kept secret!
    with open(CA_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()  # No password for simplicity
        ))
    print(f"CA private key saved to {CA_KEY_FILE}")

    # 4. Create the self-signed certificate
    
    # Define the "subject" of the certificate (who it's for)
    # For a root CA, the "issuer" and "subject" are the same.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
    ])

    # Get the public key corresponding to our private key
    public_key = private_key.public_key()

    # Build the certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365 * 10)) # Valid for 10 years

    # Add extensions. BasicConstraints(ca=True) is CRITICAL.
    # It's what makes this certificate a Certificate Authority.
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )

    # 5. Sign the certificate... with its own private key.
    certificate = builder.sign(
        private_key, hashes.SHA256(), default_backend()
    )

    # 6. Write the certificate to a file (in PEM format)
    with open(CA_CERT_FILE, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    print(f"CA certificate saved to {CA_CERT_FILE}")
    print("CA generation complete.")


if __name__ == "__main__":
    generate_ca()