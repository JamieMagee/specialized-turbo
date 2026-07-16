"""
Typed exceptions for the ``specialized_turbo.keystore`` package.

These exceptions are safe to log: none of them carry key material in
their message or attributes.
"""

from __future__ import annotations


class KeystoreError(Exception):
    """Base class for all errors raised by :mod:`specialized_turbo.keystore`."""


class InvalidEncryptionKeyError(KeystoreError):
    """Raised when key material fails validation (wrong format/length)."""
