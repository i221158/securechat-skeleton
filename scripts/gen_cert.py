"""
Issue server/client cert signed by Root CA.
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

def load_ca():
    """Helper function to load the CA's key and certificate."""
    try:
        # Load CA Private Key
        with open(CA_KEY_FILE, "rb") as f:
            ca_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        
        # Load CA Certificate
        with open(CA_CERT_FILE, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
        return ca_key, ca_cert
        
    except FileNotFoundError:
        print(f"Error: CA files not found in {CERTS_DIR}.")
        print("Please run 'python scripts/gen_ca.py' first.")
        exit(1)

def generate_signed_cert(common_name, key_file, cert_file, ca_key, ca_cert):
    """
    Generates a new keypair and a certificate signed by the CA.
    """
    print(f"Generating key and certificate for '{common_name}'...")
    
    # 1. Generate a new RSA private key for the entity (server or client)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 2. Save the entity's private key
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"  - Key saved to {key_file}")

    # 3. Create the certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name), # e.g., "localhost" or "client"
    ])

    # The issuer is the CA's subject
    issuer = ca_cert.subject
    public_key = private_key.public_key()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) # Valid for 1 year

    # Add extensions
    # BasicConstraints(ca=False) means this certificate CANNOT be used to sign other certs.
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    # Add Subject Alternative Name (SAN) for modern validation, matching the Common Name
    # This is required for Requirement 2.1.iii [cite: 165]
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False
    )

    # 4. Sign the certificate... with the CA's private key.
    certificate = builder.sign(
        ca_key, hashes.SHA256(), default_backend()
    )

    # 5. Save the new certificate
    with open(cert_file, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    print(f"  - Certificate saved to {cert_file}")

def issue_certs():
    # 1. Load the CA
    ca_key, ca_cert = load_ca()
    print("CA loaded successfully.")

    # 2. Issue Server Certificate
    # The Common Name "localhost" is important for validation [cite: 165]
    generate_signed_cert(
        common_name="localhost",
        key_file=os.path.join(CERTS_DIR, "server.key"),
        cert_file=os.path.join(CERTS_DIR, "server.crt"),
        ca_key=ca_key,
        ca_cert=ca_cert
    )
    
    # 3. Issue Client Certificate
    generate_signed_cert(
        common_name="client", # Can be any name, "client" is clear
        key_file=os.path.join(CERTS_DIR, "client.key"),
        cert_file=os.path.join(CERTS_DIR, "client.crt"),
        ca_key=ca_key,
        ca_cert=ca_cert
    )
    print("All certificates issued.")

if __name__ == "__main__":
    issue_certs()