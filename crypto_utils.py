import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secrets import token_bytes

# ---- AES-256-GCM with PBKDF2 ----
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive 32-byte AES key from password using PBKDF2-HMAC-SHA256"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode())

def aes_encrypt(plaintext: str, password: str) -> str:
    """
    Encrypts using AES-256-GCM. Returns base64(salt + nonce + ciphertext + tag)
    Format allows decryption without storing salt/nonce separately.
    """
    salt = os.urandom(16) # 128-bit salt
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12) # 96-bit nonce for GCM
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None) # ct = ciphertext + tag
    # Combine all parts for single output string
    combined = salt + nonce + ct
    return base64.b64encode(combined).decode('utf-8')

def aes_decrypt(b64_ciphertext: str, password: str) -> str:
    """
    Decrypts base64(salt + nonce + ct). Raises exception on wrong password/tampering.
    """
    try:
        combined = base64.b64decode(b64_ciphertext)
        salt, nonce, ct = combined[:16], combined[16:28], combined[28:]
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ct, None)
        return plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError("Decryption failed. Wrong password or corrupted data.") from e

# ---- XOR with Secure Random Key ----
def generate_secure_xor_key(length: int) -> bytes:
    """
    CRITICAL: Uses `secrets.token_bytes` not `random`.
    `secrets` is cryptographically secure on all OS.
    """
    if length < 1:
        raise ValueError("Key length must be positive")
    return token_bytes(length)

def xor_encrypt_decrypt(data: bytes, key: bytes) -> bytes:
    """
    XOR each byte of data with key. Key cycles if shorter than data.
    For perfect secrecy, key must be >= len(data) and used only once.
    """
    if not key:
        raise ValueError("Key cannot be empty")
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])