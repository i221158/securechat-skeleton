"""
RSA PKCS#1 v1.5 SHA-256 sign/verify.
These functions are designed to sign and verify pre-computed digests.
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils as crypto_utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

def sign(private_key: rsa.RSAPrivateKey, data_hash: bytes) -> bytes:
    """
    Signs a pre-computed SHA-256 digest using RSA-PKCS#1 v1.5.
    
    Args:
        private_key: The rsa.RSAPrivateKey object.
        data_hash: The raw 32-byte SHA-256 digest.
        
    Returns:
        The RSA signature.
    """
    try:
        signature = private_key.sign(
            data_hash,
            padding.PKCS1v15(),
            crypto_utils.Prehashed(hashes.SHA256()) # Tell sign() we already hashed
        )
        return signature
    except Exception as e:
        print(f"Error during signing: {e}")
        raise

def verify(certificate: x509.Certificate, signature: bytes, data_hash: bytes) -> bool:
    """
    Verifies an RSA-PKCS#1 v1.5 signature against a pre-computed SHA-256 digest.
    
    Args:
        certificate: The x509.Certificate object of the signer.
        signature: The signature bytes to verify.
        data_hash: The raw 32-byte SHA-256 digest of the original data.
        
    Returns:
        True if the signature is valid, False otherwise.
    """
    public_key = certificate.public_key()
    
    # Ensure the public key is RSA, though our certs should guarantee this
    if not isinstance(public_key, rsa.RSAPublicKey):
        print("Error: Certificate public key is not an RSA key.")
        return False
        
    try:
        public_key.verify(
            signature,
            data_hash,
            padding.PKCS1v15(),
            crypto_utils.Prehashed(hashes.SHA256()) # Tell verify() we already hashed
        )
        # Signature is valid
        return True
    except InvalidSignature:
        # Signature is invalid
        print("[Verify] XXX SIGNATURE VERIFICATION FAILED XXX")
        return False
    except Exception as e:
        # Other error (e.g., key mismatch)
        print(f"[Verify] Error during verification: {e}")
        return False