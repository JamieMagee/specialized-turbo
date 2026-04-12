"""
Protocol session abstraction for Specialized Turbo bikes.

Each protocol generation has a different packet framing:

- **TCU1** (TCU1, 2018 Levo): bare ``[sender][channel][data…]``, no CRC,
  no encryption.
- **TCX** (TCX+ Vado/Levo/Creo): ``[payload padded to 18B] + [CRC-16 LE]``
  = 20 bytes, optionally AES-128-CTR encrypted.  Shared by TCX2, TCX3, and
  TCX4 — they differ only in the parameter set, not the framing.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from .encryption import decrypt_packet, encrypt_packet, is_encryptable
from .framing import is_framed_packet, pack_tcx, unpack_tcx

logger = logging.getLogger(__name__)


class ProtocolSession(ABC):
    """Abstract base for protocol-generation-specific packet framing."""

    @abstractmethod
    def pack(self, payload: bytes | bytearray) -> bytes:
        """Frame *payload* for BLE transmission."""

    @abstractmethod
    def unpack(self, data: bytes | bytearray) -> bytes:
        """Strip framing from received BLE *data*, returning the raw payload."""


class TCU1Session(ProtocolSession):
    """
    TCU1 (TCU1) session — pass-through, no framing.

    Messages use the bare ``[sender][channel][data…]`` format.
    """

    def pack(self, payload: bytes | bytearray) -> bytes:
        return bytes(payload)

    def unpack(self, data: bytes | bytearray) -> bytes:
        return bytes(data)


class TCXSession(ProtocolSession):
    """
    TCX2/TCX3/TCX4 session — CRC-16 framing + optional AES-128-CTR.

    All three TCX generations share the same 20-byte packet format.
    When *key* and *iv* are provided, packets that pass
    :func:`~encryption.is_encryptable` are encrypted/decrypted.
    """

    def __init__(
        self,
        *,
        key: bytes | None = None,
        iv: bytes | None = None,
    ) -> None:
        self._key = key
        self._iv = iv

    @property
    def encrypted(self) -> bool:
        """``True`` if this session has encryption keys configured."""
        return self._key is not None and self._iv is not None

    def pack(self, payload: bytes | bytearray) -> bytes:
        """CRC-frame and optionally encrypt *payload*."""
        framed = pack_tcx(payload)
        if self.encrypted and is_encryptable(framed):
            assert self._key is not None and self._iv is not None
            return encrypt_packet(self._key, self._iv, framed)
        return framed

    def unpack(self, data: bytes | bytearray) -> bytes:
        """Optionally decrypt and CRC-validate received *data*."""
        if self.encrypted and is_encryptable(data):
            assert self._key is not None and self._iv is not None
            data = decrypt_packet(self._key, self._iv, data)
        if is_framed_packet(data):
            return unpack_tcx(data)
        # Fall through for non-framed data (NAK, etc.)
        return bytes(data)
