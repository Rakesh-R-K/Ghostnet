import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key(password: str = None, salt: bytes = None) -> bytes:
    """
    Generates a 32-byte key for ChaCha20Poly1305.
    If password is provided, derives key using PBKDF2.
    Otherwise returns a random key.
    """
    if password:
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        return key, salt
    else:
        return ChaCha20Poly1305.generate_key()

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Encrypts data using ChaCha20Poly1305.
    Returns nonce + ciphertext + tag (tag is included in ciphertext by cryptography lib).
    """
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = chacha.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypts data using ChaCha20Poly1305.
    Expects nonce (12 bytes) prepended to ciphertext.
    """
    chacha = ChaCha20Poly1305(key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return chacha.decrypt(nonce, ciphertext, None)

if __name__ == "__main__":
    # Simple test
    key = generate_key()
    msg = b"Secret Message"
    enc = encrypt_data(msg, key)
    dec = decrypt_data(enc, key)
    print(f"Original: {msg}")
    print(f"Decrypted: {dec}")
    assert msg == dec
