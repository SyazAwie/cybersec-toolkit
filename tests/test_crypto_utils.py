import pytest
import base64
import sys
import os

# Add the parent directory to the system path so it can find your utils
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_utils import aes_encrypt, aes_decrypt, xor_encrypt_decrypt, generate_secure_xor_key

def test_aes_encrypt_decrypt_roundtrip():
    password = "TestPass123!"
    plaintext = "Hello UiTM Cybersecurity!"
    ciphertext = aes_encrypt(plaintext, password)
    assert ciphertext != plaintext
    decrypted = aes_decrypt(ciphertext, password)
    assert decrypted == plaintext

def test_aes_wrong_password_fails():
    plaintext = "Secret data"
    ciphertext = aes_encrypt(plaintext, "correct_password")
    with pytest.raises(ValueError, match="Decryption failed"):
        aes_decrypt(ciphertext, "wrong_password")

def test_aes_tampered_ciphertext_fails():
    ciphertext = aes_encrypt("data", "pass")
    tampered = base64.b64decode(ciphertext)
    tampered = base64.b64encode(tampered[:-1] + b'\x00').decode() # flip last byte
    with pytest.raises(ValueError):
        aes_decrypt(tampered, "pass")

def test_xor_encrypt_decrypt_roundtrip():
    key = generate_secure_xor_key(32)
    data = b"Portfolio demo text"
    encrypted = xor_encrypt_decrypt(data, key)
    assert encrypted != data
    decrypted = xor_encrypt_decrypt(encrypted, key)
    assert decrypted == data

def test_xor_key_is_random():
    key1 = generate_secure_xor_key(16)
    key2 = generate_secure_xor_key(16)
    assert key1 != key2 # Extremely unlikely to collide
    assert len(key1) == 16

def test_xor_empty_key_fails():
    with pytest.raises(ValueError):
        xor_encrypt_decrypt(b"test", b"")