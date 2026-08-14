"""
Secret-safe container for a bike's AES-128 encryption key.

``BikeEncryptionKey`` only *validates and wraps* key material that the
caller already possesses -- it has no BLE or network capability of its
own and cannot retrieve a key on your behalf. Wrapped (``wrapped_base64``)
key material comes from the account-linked Specialized keystore service.

This package intentionally does not implement any such retrieval itself:
there is no backend HTTP client here, and the bike does not send the fixed key
over BLE. Supplying valid key material remains the caller's responsibility.
"""

from __future__ import annotations

from ..encryption import derive_key
from .exceptions import InvalidEncryptionKeyError

_WRAPPED_KEY_LENGTH = 64
_RAW_KEY_LENGTH = 16


class BikeEncryptionKey:
    """
    A validated 16-byte AES-128 bike encryption key.

    Secret-safe: the raw key material is never exposed through
    ``repr()``, ``str()``, equality checks, or exception messages.
    Access the raw bytes explicitly via the ``raw`` property only when
    handing them to :mod:`specialized_turbo.encryption`.

    Construct with exactly one of:

    - ``wrapped_base64``: the official 64-character base64-encoded key,
      returned by the account keystore service. Derived via
      :func:`specialized_turbo.encryption.derive_key`. This class cannot
      retrieve it itself.
    - ``raw``: an already-derived 16-byte key, as ``bytes``/``bytearray``
      or a 32-character hex string.
    """

    __slots__ = ("_key",)

    def __init__(
        self,
        *,
        wrapped_base64: str | None = None,
        raw: bytes | bytearray | str | None = None,
    ) -> None:
        if (wrapped_base64 is None) == (raw is None):
            raise ValueError("Exactly one of wrapped_base64 or raw must be provided")

        if wrapped_base64 is not None:
            key = self._derive_from_wrapped(wrapped_base64)
        else:
            assert raw is not None
            key = self._decode_raw(raw)

        if len(key) != _RAW_KEY_LENGTH:
            raise InvalidEncryptionKeyError(
                f"Encryption key must be {_RAW_KEY_LENGTH} bytes, got {len(key)}"
            )
        self._key = bytes(key)

    @staticmethod
    def _derive_from_wrapped(wrapped_base64: str) -> bytes:
        if len(wrapped_base64) != _WRAPPED_KEY_LENGTH:
            raise InvalidEncryptionKeyError(
                f"Wrapped key must be {_WRAPPED_KEY_LENGTH} characters, "
                f"got {len(wrapped_base64)}"
            )
        try:
            return derive_key(wrapped_base64)
        except Exception as exc:
            # Deliberately drop the original exception (and its message,
            # which may echo back fragments of the invalid input) --
            # only the exception type is safe to surface.
            raise InvalidEncryptionKeyError(
                f"Failed to derive key from wrapped base64 value ({type(exc).__name__})"
            ) from None

    @staticmethod
    def _decode_raw(raw: bytes | bytearray | str) -> bytes:
        if isinstance(raw, str):
            try:
                return bytes.fromhex(raw)
            except ValueError:
                raise InvalidEncryptionKeyError(
                    "raw key string must be valid hexadecimal"
                ) from None
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw)
        raise InvalidEncryptionKeyError(
            f"raw key must be bytes, bytearray, or a hex string, got {type(raw).__name__}"
        )

    @property
    def raw(self) -> bytes:
        """The raw 16-byte AES-128 key. Handle with care -- do not log."""
        return self._key

    def __repr__(self) -> str:
        return "BikeEncryptionKey(<redacted>)"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BikeEncryptionKey):
            return NotImplemented
        return self._key == other._key

    def __hash__(self) -> int:
        return hash(self._key)
