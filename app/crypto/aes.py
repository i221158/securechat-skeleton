"""
AES-128(ECB)+PKCS#7 helpers (use library).
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts plaintext using AES-128-ECB with PKCS#7 padding.
    """
    # 1. Create PKCS#7 padder
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # 2. Create AES-ECB cipher
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 3. Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts ciphertext using AES-128-ECB and removes PKCS#7 padding.
    """
    # 1. Create AES-ECB cipher
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # 2. Decrypt
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 3. Remove PKCS#7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext
    except ValueError:
        # This happens if the key is wrong or padding is bad
        raise Exception("Failed to decrypt or unpad data. Check key and ciphertext.")