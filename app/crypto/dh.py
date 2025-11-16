"""
Classic DH helpers + Trunc16(SHA256(Ks)) derivation.
This version passes public *numbers* (p, g, y) instead of key objects.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

def generate_client_dh():
    """
    Generates DH parameters (p, g) and a client keypair (a, A).
    
    Returns:
        client_private_key (DHPrivateKey): The client's private key 'a'.
        p (int): The prime modulus.
        g (int): The generator.
        A_y (int): The client's public value 'A'.
    """
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g
    A_y = public_key.public_numbers().y

    return private_key, p, g, A_y

def get_server_dh_secret(p: int, g: int, A_y: int):
    """
    Generates a server keypair (b, B) and the shared secret (Ks).
    
    Args:
        p (int): The prime modulus from the client.
        g (int): The generator from the client.
        A_y (int): The client's public value 'A'.
        
    Returns:
        B_y (int): The server's public value 'B'.
        shared_secret_Ks_bytes (bytes): The shared secret 'Ks'.
    """
    # 1. Reconstruct client's parameters and public key
    pn = dh.DHParameterNumbers(p, g)
    params = pn.parameters(default_backend())
    client_public_numbers = dh.DHPublicNumbers(A_y, pn)
    client_public_key = client_public_numbers.public_key(default_backend())
    
    # 2. Generate server private key 'b'
    private_key = params.generate_private_key()
    
    # 3. Compute server public value 'B_y'
    B_y = private_key.public_key().public_numbers().y
    
    # 4. Compute shared secret 'Ks'
    shared_secret_Ks_bytes = private_key.exchange(client_public_key)
    
    return B_y, shared_secret_Ks_bytes

def get_client_dh_shared_secret(p: int, g: int, B_y: int, client_private_key: dh.DHPrivateKey):
    """
    Computes the client's view of the shared secret (Ks).
    
    Args:
        p (int): The prime modulus.
        g (int): The generator.
        B_y (int): The server's public value 'B'.
        client_private_key (DHPrivateKey): The client's private key 'a'.
        
    Returns:
        shared_secret_Ks_bytes (bytes): The shared secret 'Ks'.
    """
    # 1. Reconstruct server's public key
    pn = dh.DHParameterNumbers(p, g)
    server_public_numbers = dh.DHPublicNumbers(B_y, pn)
    server_public_key = server_public_numbers.public_key(default_backend())
    
    # 2. Compute shared secret 'Ks'
    shared_secret_Ks_bytes = client_private_key.exchange(server_public_key)
    
    return shared_secret_Ks_bytes


def derive_aes_key(shared_secret_Ks: bytes) -> bytes:
    """
    Derives the 16-byte AES key from the shared secret.
    K = Trunc16(SHA256(big-endian(Ks)))
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_secret_Ks)
    full_hash = digest.finalize()
    
    # Truncate to 16 bytes for AES-128
    return full_hash[:16]