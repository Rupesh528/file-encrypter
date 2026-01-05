"""
crypto.py
----------
Handles all cryptographic operations and file encryption/decryption.
"""

import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a secure AES key from a password using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_file_inplace(filepath: str, password: str):
    """
    Encrypts the ORIGINAL file by overwriting its contents.
    """
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(filepath, "rb") as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)

    with open(filepath, "wb") as f:
        f.write(salt + encrypted_data)


def decrypt_file_inplace(filepath: str, password: str):
    """
    Decrypts the ORIGINAL encrypted file by overwriting its contents.
    """
    with open(filepath, "rb") as f:
        salt = f.read(16)
        encrypted_data = f.read()

    key = derive_key(password, salt)
    fernet = Fernet(key)

    decrypted_data = fernet.decrypt(encrypted_data)

    with open(filepath, "wb") as f:
        f.write(decrypted_data)
