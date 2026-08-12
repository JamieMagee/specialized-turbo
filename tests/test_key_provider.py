"""Tests for encryption-key provider interfaces."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from specialized_turbo.encryption import PRODUCTION_WRAPPING_KEY
from specialized_turbo.key_provider import (
    EncryptionKeyProviderError,
    StaticKeyProvider,
    resolve_bike_key,
)


def _wrapped_key(expected: bytes) -> str:
    wrapping_iv = bytes(range(16))
    cipher = Cipher(
        algorithms.AES(PRODUCTION_WRAPPING_KEY),
        modes.CTR(wrapping_iv),
    )
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(expected.hex().encode()) + encryptor.finalize()
    return base64.b64encode(wrapping_iv + encrypted).decode()


async def test_static_key_provider_resolves_key() -> None:
    expected = bytes.fromhex("00112233445566778899aabbccddeeff")
    provider = StaticKeyProvider(_wrapped_key(expected))

    key = await resolve_bike_key(
        provider,
        hmi_hardware="3.2.1",
        hmi_serial="123456789",
    )

    assert key == expected


async def test_provider_errors_are_typed() -> None:
    provider = StaticKeyProvider("invalid")

    with pytest.raises(EncryptionKeyProviderError):
        await resolve_bike_key(
            provider,
            hmi_hardware="3.2.1",
            hmi_serial="123456789",
        )
