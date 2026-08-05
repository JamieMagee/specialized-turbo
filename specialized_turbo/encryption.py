"""
AES-128-CTR encryption for Specialized Turbo TCX2/TCX3/TCX4 protocols.

Packets are 20 bytes after CRC framing.  The encryption layout is:

    [param_id: 2B] [encrypted_body: 16B] [encrypted_tail: 2B]

Bytes 0-1 (the parameter ID) are sent in the clear.  Bytes 2-17 and 18-19
are encrypted with AES-128-CTR using a per-session key and IV.

Not all packets are encrypted: NAK (``0x0A``) and F8 FF-prefixed packets
are always transmitted in the clear.
"""

from __future__ import annotations

import base64
import logging

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .framing import FRAMED_PACKET_SIZE, NAK_BYTE

logger = logging.getLogger(__name__)

# Header bytes that indicate a packet should NOT be encrypted
_CLEAR_PREFIX = b"\xf8\xff"


def is_encryptable(data: bytes | bytearray) -> bool:
    """Return ``True`` if *data* should be encrypted/decrypted."""
    if len(data) == 0:
        return False
    if len(data) == 1 and data[0] == NAK_BYTE:
        return False
    return len(data) < 2 or data[:2] != _CLEAR_PREFIX


def _aes_ctr_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CTR encrypt or decrypt (symmetric operation)."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def encrypt_packet(key: bytes, iv: bytes, data: bytes | bytearray) -> bytes:
    """
    Encrypt a 20-byte CRC-framed TCX packet.

    The 2-byte header (parameter ID) is preserved in the clear.
    Bytes 2-19 are encrypted with AES-128-CTR.

    Returns the encrypted 20-byte packet.
    """
    if len(data) != FRAMED_PACKET_SIZE:
        raise ValueError(f"Expected {FRAMED_PACKET_SIZE} bytes, got {len(data)}")
    if not is_encryptable(data):
        return bytes(data)
    header = bytes(data[:2])
    body = bytes(data[2:])
    encrypted_body = _aes_ctr_crypt(key, iv, body)
    return header + encrypted_body


def decrypt_packet(key: bytes, iv: bytes, data: bytes | bytearray) -> bytes:
    """
    Decrypt a 20-byte encrypted TCX packet.

    The 2-byte header (parameter ID) is already in the clear.
    Bytes 2-19 are decrypted with AES-128-CTR.

    Returns the decrypted 20-byte packet.
    """
    if len(data) != FRAMED_PACKET_SIZE:
        raise ValueError(f"Expected {FRAMED_PACKET_SIZE} bytes, got {len(data)}")
    if not is_encryptable(data):
        return bytes(data)
    header = bytes(data[:2])
    body = bytes(data[2:])
    decrypted_body = _aes_ctr_crypt(key, iv, body)
    return header + decrypted_body


def derive_key(base64_key: str) -> bytes:
    """
    Derive the AES-128 encryption key from the bike's BTEncryptionInfo.

    The *base64_key* is a 64-character base64-encoded string from the bike's
    advertisement data.  Key derivation:

    1. Base64-decode the 64-char string (→ 48 raw bytes).
    2. First 16 bytes are the intermediate AES key.
    3. Remaining bytes are AES-CTR encrypted with the intermediate key.
    4. Decrypt them, then hex-decode the result → final 16-byte AES key.
    """
    raw = base64.b64decode(base64_key)
    if len(raw) < 17:
        raise ValueError(
            f"Base64-decoded key too short ({len(raw)} bytes), need at least 17"
        )
    intermediate_key = raw[:16]
    encrypted_rest = raw[16:]
    # Decrypt with a zero IV (the native code uses the iv_vector parameter,
    # which is set to zeros during key derivation)
    iv = b"\x00" * 16
    decrypted_hex = _aes_ctr_crypt(intermediate_key, iv, encrypted_rest)
    try:
        return bytes.fromhex(decrypted_hex.decode("ascii"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"Key derivation failed: {exc}") from exc
