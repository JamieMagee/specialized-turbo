"""Encryption-key provider interfaces for modern Specialized Turbo bikes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .encryption import unwrap_keystore_key


class EncryptionKeyRequiredError(RuntimeError):
    """Raised when a bike declares encryption but no key is available."""


class EncryptionKeyProviderError(RuntimeError):
    """Raised when an encryption-key provider cannot return a usable key."""


class EncryptionKeyProvider(Protocol):
    """Resolve a wrapped Specialized key for one HMI."""

    async def get_wrapped_key(
        self,
        *,
        hmi_hardware: str,
        hmi_serial: str,
    ) -> str:
        """Return the 64-character wrapped key for an HMI."""


@dataclass(frozen=True, slots=True)
class StaticKeyProvider:
    """Return one caller-supplied wrapped key."""

    wrapped_key: str

    async def get_wrapped_key(
        self,
        *,
        hmi_hardware: str,
        hmi_serial: str,
    ) -> str:
        del hmi_hardware, hmi_serial
        return self.wrapped_key


async def resolve_bike_key(
    provider: EncryptionKeyProvider,
    *,
    hmi_hardware: str,
    hmi_serial: str,
) -> bytes:
    """Resolve and unwrap the 16-byte AES key for one bike."""
    try:
        wrapped_key = await provider.get_wrapped_key(
            hmi_hardware=hmi_hardware,
            hmi_serial=hmi_serial,
        )
        return unwrap_keystore_key(wrapped_key)
    except EncryptionKeyProviderError:
        raise
    except Exception as exc:
        raise EncryptionKeyProviderError(
            f"Failed to resolve encryption key for HMI {hmi_hardware}"
        ) from exc
