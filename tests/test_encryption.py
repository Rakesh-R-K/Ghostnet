import pytest
from common import encryption_utils

def test_key_generation():
    key = encryption_utils.generate_key()
    assert len(key) == 32

def test_password_derived_key():
    passw = "supersecret"
    key1, salt1 = encryption_utils.generate_key(passw)
    key2, salt2 = encryption_utils.generate_key(passw, salt=salt1)
    
    assert key1 == key2
    assert len(key1) == 32

def test_encryption_decryption():
    key = encryption_utils.generate_key()
    data = b"Confidential Data"
    
    encrypted = encryption_utils.encrypt_data(data, key)
    assert encrypted != data
    
    decrypted = encryption_utils.decrypt_data(encrypted, key)
    assert decrypted == data

def test_decryption_failure():
    key1 = encryption_utils.generate_key()
    key2 = encryption_utils.generate_key()
    data = b"Secret"
    
    encrypted = encryption_utils.encrypt_data(data, key1)
    with pytest.raises(Exception):
        encryption_utils.decrypt_data(encrypted, key2)
