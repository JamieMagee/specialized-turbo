"""
Offline, secret-safe bike encryption key support.

This subpackage is intentionally isolated from the rest of
``specialized_turbo``: it is not imported by the top-level package
``__init__.py`` and has no effect on BLE connection, CLI, or protocol
behavior. Import directly from ``specialized_turbo.keystore`` to use it.

It contains only :class:`BikeEncryptionKey` (a validated, secret-safe
wrapper around AES-128 key material) and its typed exceptions. There is
no account/backend HTTP client here, and no optional dependency is
required -- everything in this package imports cleanly with only the
base ``specialized-turbo`` install.
"""

from __future__ import annotations

from .exceptions import (
    InvalidEncryptionKeyError as InvalidEncryptionKeyError,
)
from .exceptions import (
    KeystoreError as KeystoreError,
)
from .models import BikeEncryptionKey as BikeEncryptionKey

__all__ = [
    "BikeEncryptionKey",
    "InvalidEncryptionKeyError",
    "KeystoreError",
]
