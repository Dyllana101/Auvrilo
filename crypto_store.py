import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class EncryptionKeyError(ValueError):
    pass


def _derive_key(secret: str, purpose: str) -> bytes:
    if len(secret) < 32:
        raise EncryptionKeyError("AUVRILO_ENCRYPTION_KEY must be at least 32 characters")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"auvrilo-storage-v1",
        info=f"auvrilo:{purpose}".encode("utf-8"),
    ).derive(secret.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, secret: str, purpose: str, account_id: str) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    aad = f"auvrilo:{purpose}:{account_id}".encode("utf-8")
    ciphertext = AESGCM(_derive_key(secret, purpose)).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_bytes(nonce: bytes, ciphertext: bytes, secret: str, purpose: str, account_id: str) -> bytes:
    aad = f"auvrilo:{purpose}:{account_id}".encode("utf-8")
    return AESGCM(_derive_key(secret, purpose)).decrypt(nonce, ciphertext, aad)
