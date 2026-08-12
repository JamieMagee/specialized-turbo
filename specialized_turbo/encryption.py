"""AES-128-CTR support for Specialized Turbo TCX2+ protocols.

CRC-framed packets use this wire layout::

    [parameter ID: 2B clear] [payload: 16B encrypted] [CRC-16: 2B clear]

The per-bike AES key is returned by Specialized's keystore service as a
64-character wrapped value. The bike provides a fresh packet IV through
``SYSTEM_GET_NEW_VI`` during identification.
"""

from __future__ import annotations

import base64
import binascii

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .framing import FRAMED_PACKET_SIZE, NAK_BYTE

_CLEAR_PREFIX = b"\xf8\xff"
PRODUCTION_WRAPPING_KEY = b"nZr4u7x!A%D*G-Ka"
STAGING_WRAPPING_KEY = b"/A?D(G+KbPeShVmY"
_WRAPPED_KEY_LENGTH = 64
_DECODED_WRAPPED_KEY_LENGTH = 48
_AES_BLOCK_SIZE = 16


class EncryptionError(ValueError):
    """Base error for invalid Specialized encryption material."""


class WrappedKeyError(EncryptionError):
    """Raised when a keystore response cannot be unwrapped."""


def is_encryptable(data: bytes | bytearray) -> bool:
    """Return ``True`` if *data* should be encrypted/decrypted."""
    if len(data) == 0:
        return False
    if len(data) == 1 and data[0] == NAK_BYTE:
        return False
    return len(data) < 2 or data[:2] != _CLEAR_PREFIX


def _aes_ctr_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CTR encrypt or decrypt (symmetric operation)."""
    if len(key) != _AES_BLOCK_SIZE:
        raise EncryptionError(f"Expected a 16-byte AES key, got {len(key)}")
    if len(iv) != _AES_BLOCK_SIZE:
        raise EncryptionError(f"Expected a 16-byte AES IV, got {len(iv)}")
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def encrypt_packet(key: bytes, iv: bytes, data: bytes | bytearray) -> bytes:
    """
    Encrypt a 20-byte CRC-framed TCX packet.

    The 2-byte parameter ID and trailing 2-byte CRC are preserved in the clear.
    Only bytes 2-17 are encrypted with AES-128-CTR.

    Returns the encrypted 20-byte packet.
    """
    if len(data) != FRAMED_PACKET_SIZE:
        raise ValueError(f"Expected {FRAMED_PACKET_SIZE} bytes, got {len(data)}")
    if not is_encryptable(data):
        return bytes(data)
    return (
        bytes(data[:2]) + _aes_ctr_crypt(key, iv, bytes(data[2:18])) + bytes(data[18:])
    )


def decrypt_packet(key: bytes, iv: bytes, data: bytes | bytearray) -> bytes:
    """
    Decrypt a 20-byte encrypted TCX packet.

    The 2-byte parameter ID and trailing 2-byte CRC are already in the clear.
    Only bytes 2-17 are decrypted with AES-128-CTR.

    Returns the decrypted 20-byte packet.
    """
    if len(data) != FRAMED_PACKET_SIZE:
        raise ValueError(f"Expected {FRAMED_PACKET_SIZE} bytes, got {len(data)}")
    if not is_encryptable(data):
        return bytes(data)
    return (
        bytes(data[:2]) + _aes_ctr_crypt(key, iv, bytes(data[2:18])) + bytes(data[18:])
    )


def unwrap_keystore_key(
    wrapped_key: str,
    *,
    wrapping_key: bytes = PRODUCTION_WRAPPING_KEY,
) -> bytes:
    """Unwrap a 64-character key returned by Specialized's keystore service."""
    if len(wrapped_key) != _WRAPPED_KEY_LENGTH:
        raise WrappedKeyError(
            f"Expected a 64-character wrapped key, got {len(wrapped_key)}"
        )

    try:
        raw = base64.b64decode(wrapped_key, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise WrappedKeyError("Wrapped key is not valid base64") from exc

    if len(raw) != _DECODED_WRAPPED_KEY_LENGTH:
        raise WrappedKeyError(f"Expected 48 decoded bytes, got {len(raw)}")

    wrapping_iv = raw[:_AES_BLOCK_SIZE]
    encrypted_hex_key = raw[_AES_BLOCK_SIZE:]
    decrypted_hex = _aes_ctr_crypt(wrapping_key, wrapping_iv, encrypted_hex_key)

    try:
        key = bytes.fromhex(decrypted_hex.decode("ascii"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise WrappedKeyError(
            "Wrapped key did not decrypt to an ASCII hex key"
        ) from exc

    if len(key) != _AES_BLOCK_SIZE:
        raise WrappedKeyError(f"Expected a 16-byte bike key, got {len(key)}")
    return key


def derive_key(base64_key: str) -> bytes:
    """Compatibility alias for :func:`unwrap_keystore_key`."""
    return unwrap_keystore_key(base64_key)
