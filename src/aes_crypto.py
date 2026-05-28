"""AES-CBC shellcode encryption helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class EncryptParams:
    """Holds the AES key and IV used to encrypt the shellcode."""

    key: bytes  # 16, 24, or 32 bytes  (AES-128 / 192 / 256)
    iv: bytes   # always 16 bytes

    @property
    def bits(self) -> int:
        return len(self.key) * 8

    def key_hex(self) -> str:
        return self.key.hex()

    def iv_hex(self) -> str:
        return self.iv.hex()


# ---------------------------------------------------------------------------
# Key / IV helpers
# ---------------------------------------------------------------------------

def generate_key(bits: int = 256) -> bytes:
    if bits not in (128, 192, 256):
        raise ValueError(f"AES key size must be 128, 192, or 256 bits; got {bits}")
    return os.urandom(bits // 8)


def generate_iv() -> bytes:
    return os.urandom(16)


def parse_hex_key(hex_str: str) -> bytes:
    """
    Parse a hex-encoded AES key from the command line.
    Accepts 32 hex chars (AES-128), 48 (AES-192), or 64 (AES-256).
    """
    s = hex_str.strip()
    valid = {32: 128, 48: 192, 64: 256}
    if len(s) not in valid:
        raise ValueError(
            f"--aes-key: expected 32 (AES-128), 48 (AES-192), or 64 (AES-256) "
            f"hex characters; got {len(s)}"
        )
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise ValueError("--aes-key: contains non-hex characters")


def parse_hex_iv(hex_str: str) -> bytes:
    """Parse a hex-encoded 16-byte AES IV from the command line."""
    s = hex_str.strip()
    if len(s) != 32:
        raise ValueError(
            f"--aes-iv: expected 32 hex characters (16 bytes); got {len(s)}"
        )
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise ValueError("--aes-iv: contains non-hex characters")


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def encrypt_shellcode(
    data: bytes,
    key: bytes | None = None,
    iv: bytes | None = None,
    bits: int = 256,
) -> tuple[bytes, EncryptParams]:
    """
    AES-CBC encrypt *data* with PKCS7 padding.

    If *key* / *iv* are None, fresh random values are generated.
    Returns (ciphertext, EncryptParams).

    Requires: pycryptodome  (pip install pycryptodome)
    """
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
    except ImportError as exc:
        raise ImportError(
            "pycryptodome is required for AES encryption. "
            "Run: pip install pycryptodome"
        ) from exc

    if key is None:
        key = generate_key(bits)
    if iv is None:
        iv = generate_iv()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext, EncryptParams(key=key, iv=iv)
