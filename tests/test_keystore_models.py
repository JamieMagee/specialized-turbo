"""
Unit tests for specialized_turbo.keystore.models — BikeEncryptionKey.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from specialized_turbo.keystore.exceptions import InvalidEncryptionKeyError
from specialized_turbo.keystore.models import BikeEncryptionKey

FINAL_KEY = bytes(range(16))
INTERMEDIATE_KEY = bytes(range(100, 116))


def make_wrapped_key(
    final_key: bytes = FINAL_KEY, intermediate_key: bytes = INTERMEDIATE_KEY
) -> str:
    """Build a valid 64-char wrapped base64 key that derive_key() can decode."""
    hex_ascii = final_key.hex().encode("ascii")
    iv = b"\x00" * 16
    cipher = Cipher(algorithms.AES(intermediate_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    encrypted_rest = encryptor.update(hex_ascii) + encryptor.finalize()
    raw = intermediate_key + encrypted_rest
    return base64.b64encode(raw).decode("ascii")


class TestConstructionFromWrapped:
    def test_valid_wrapped_key(self):
        wrapped = make_wrapped_key()
        key = BikeEncryptionKey(wrapped_base64=wrapped)
        assert key.raw == FINAL_KEY

    def test_wrong_length_wrapped_key(self):
        with pytest.raises(InvalidEncryptionKeyError, match="64 characters"):
            BikeEncryptionKey(wrapped_base64="short")

    def test_invalid_base64_wrapped_key(self):
        # Correct length (64 chars) but not valid base64 content.
        with pytest.raises(InvalidEncryptionKeyError, match="Failed to derive key"):
            BikeEncryptionKey(wrapped_base64="!" * 64)

    def test_derivation_failure_message_has_no_key_content(self):
        bogus = "!" * 64
        with pytest.raises(InvalidEncryptionKeyError) as exc_info:
            BikeEncryptionKey(wrapped_base64=bogus)
        assert bogus not in str(exc_info.value)


class TestConstructionFromRaw:
    def test_raw_bytes(self):
        key = BikeEncryptionKey(raw=FINAL_KEY)
        assert key.raw == FINAL_KEY

    def test_raw_bytearray(self):
        key = BikeEncryptionKey(raw=bytearray(FINAL_KEY))
        assert key.raw == FINAL_KEY

    def test_raw_hex_string(self):
        key = BikeEncryptionKey(raw=FINAL_KEY.hex())
        assert key.raw == FINAL_KEY

    def test_raw_wrong_length(self):
        with pytest.raises(InvalidEncryptionKeyError, match="16 bytes"):
            BikeEncryptionKey(raw=b"\x00" * 8)

    def test_raw_invalid_hex(self):
        with pytest.raises(InvalidEncryptionKeyError, match="hexadecimal"):
            BikeEncryptionKey(raw="not-hex-zz")

    def test_raw_wrong_type(self):
        bad_raw: Any = 12345
        with pytest.raises(InvalidEncryptionKeyError, match="must be bytes"):
            BikeEncryptionKey(raw=bad_raw)


class TestConstructionArgumentValidation:
    def test_neither_argument_raises(self):
        with pytest.raises(ValueError, match="Exactly one of"):
            BikeEncryptionKey()

    def test_both_arguments_raises(self):
        with pytest.raises(ValueError, match="Exactly one of"):
            BikeEncryptionKey(wrapped_base64=make_wrapped_key(), raw=FINAL_KEY)


class TestSecretSafety:
    def test_repr_is_redacted(self):
        key = BikeEncryptionKey(raw=FINAL_KEY)
        assert FINAL_KEY.hex() not in repr(key)
        assert "redacted" in repr(key)

    def test_str_is_redacted(self):
        key = BikeEncryptionKey(raw=FINAL_KEY)
        assert FINAL_KEY.hex() not in str(key)
        assert "redacted" in str(key)

    def test_fstring_does_not_leak(self):
        key = BikeEncryptionKey(raw=FINAL_KEY)
        assert FINAL_KEY.hex() not in f"{key}"

    def test_log_redaction(self, caplog: pytest.LogCaptureFixture):
        key = BikeEncryptionKey(raw=FINAL_KEY)
        with caplog.at_level(logging.DEBUG):
            logging.getLogger(__name__).info("got key %s", key)
        assert FINAL_KEY.hex() not in caplog.text

    def test_no_dict_leakage(self):
        key = BikeEncryptionKey(raw=FINAL_KEY)
        with pytest.raises(TypeError):
            vars(key)


class TestEquality:
    def test_equal_keys(self):
        assert BikeEncryptionKey(raw=FINAL_KEY) == BikeEncryptionKey(
            raw=FINAL_KEY.hex()
        )

    def test_different_keys_not_equal(self):
        other = bytes(reversed(FINAL_KEY))
        assert BikeEncryptionKey(raw=FINAL_KEY) != BikeEncryptionKey(raw=other)

    def test_not_equal_to_other_type(self):
        assert BikeEncryptionKey(raw=FINAL_KEY) != FINAL_KEY

    def test_hashable(self):
        key = BikeEncryptionKey(raw=FINAL_KEY)
        assert hash(key) == hash(BikeEncryptionKey(raw=FINAL_KEY))
