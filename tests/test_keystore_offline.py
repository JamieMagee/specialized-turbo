"""
Tests that specialized_turbo.keystore is fully offline: no HTTP client,
no aiohttp dependency, and no import-time reliance on network libraries.
"""

from __future__ import annotations

import subprocess
import sys

import specialized_turbo.keystore as ks


class TestPackageSurface:
    def test_exports_only_key_model_and_exceptions(self):
        assert set(ks.__all__) == {
            "BikeEncryptionKey",
            "KeystoreError",
            "InvalidEncryptionKeyError",
        }

    def test_no_http_client_symbols(self):
        for name in ("KeystoreClient", "DEFAULT_BASE_URL", "client"):
            assert not hasattr(ks, name)

    def test_invalid_encryption_key_error_is_keystore_error(self):
        assert issubclass(ks.InvalidEncryptionKeyError, ks.KeystoreError)


class TestNoAiohttpDependency:
    def test_importing_keystore_does_not_import_aiohttp(self):
        script = (
            "import sys\n"
            "import specialized_turbo.keystore\n"
            "assert 'aiohttp' not in sys.modules, sorted(sys.modules)\n"
            "print('OK')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout

    def test_keystore_imports_without_aiohttp_installed(self):
        """Even if aiohttp is entirely absent, the keystore package must
        still import cleanly -- it has no dependency on it at all."""
        script = (
            "import sys\n"
            "sys.modules['aiohttp'] = None\n"
            "import specialized_turbo.keystore as ks\n"
            "assert ks.BikeEncryptionKey is not None\n"
            "assert ks.KeystoreError is not None\n"
            "assert ks.InvalidEncryptionKeyError is not None\n"
            "print('OK')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout
