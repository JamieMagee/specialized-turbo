"""Tests for the specialized-turbo command-line interface."""

from __future__ import annotations

import argparse
import json
from typing import Self
from unittest.mock import AsyncMock, MagicMock

import pytest

import specialized_turbo.cloud as cloud_module
from specialized_turbo import cli
from specialized_turbo.cloud import CloudAuthenticationError, CloudRequestError
from specialized_turbo.protocol import (
    BikeAdvertisement,
    BLEProfile,
    ProtocolEncryptionMethod,
)


class _FakeCloud:
    def __init__(
        self,
        *,
        wrapped_key: str = "A" * 64,
        error: Exception | None = None,
    ) -> None:
        self.wrapped_key = wrapped_key
        self.error = error
        self.closed = False
        self.login_args: tuple[str, str] | None = None
        self.key_args: tuple[str, str] | None = None

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.closed = True

    async def login(self, email: str, password: str) -> None:
        self.login_args = (email, password)
        if isinstance(self.error, CloudAuthenticationError):
            raise self.error

    async def get_wrapped_key(
        self,
        *,
        hmi_hardware: str,
        hmi_serial: str,
    ) -> str:
        self.key_args = (hmi_hardware, hmi_serial)
        if self.error is not None:
            raise self.error
        return self.wrapped_key


def _args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "address": None,
        "email": "rider@example.com",
        "hmi_hardware": "3.2.1",
        "hmi_serial": "123456789",
        "scan_timeout": 10.0,
        "json_output": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


async def test_fetch_key_plain_output_with_explicit_hmi(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake = _FakeCloud()
    lookup = AsyncMock()
    monkeypatch.setattr(cli, "find_bike_advertisement_by_address", lookup)
    monkeypatch.setattr(cloud_module, "SpecializedCloudClient", lambda: fake)
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "secret")

    await cli._cmd_fetch_key(_args())

    assert capsys.readouterr().out == f"{'A' * 64}\n"
    lookup.assert_not_awaited()
    assert fake.login_args == ("rider@example.com", "secret")
    assert fake.key_args == ("3.2.1", "123456789")
    assert fake.closed


async def test_fetch_key_json_uses_scanned_hmi(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    advertisement = BikeAdvertisement(
        generation=BLEProfile.TCX,
        encryption=ProtocolEncryptionMethod.AES_CTR,
        hmi_hardware="4.5.6",
        hmi_serial="987654321",
    )
    lookup = AsyncMock(return_value=(MagicMock(), MagicMock(), advertisement))
    fake = _FakeCloud(wrapped_key="B" * 64)
    monkeypatch.setattr(cli, "find_bike_advertisement_by_address", lookup)
    monkeypatch.setattr(cloud_module, "SpecializedCloudClient", lambda: fake)
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "secret")

    await cli._cmd_fetch_key(
        _args(
            address="AA:BB:CC:DD:EE:FF",
            hmi_hardware=None,
            hmi_serial=None,
            json_output=True,
        )
    )

    assert json.loads(capsys.readouterr().out) == {
        "address": "AA:BB:CC:DD:EE:FF",
        "hmi_hardware": "4.5.6",
        "hmi_serial": "987654321",
        "wrapped_key": "B" * 64,
    }
    lookup.assert_awaited_once_with("AA:BB:CC:DD:EE:FF", timeout=10.0)


async def test_fetch_key_explicit_value_overrides_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advertisement = BikeAdvertisement(
        generation=BLEProfile.TCX,
        encryption=ProtocolEncryptionMethod.AES_CTR,
        hmi_hardware="4.5.6",
        hmi_serial="987654321",
    )
    monkeypatch.setattr(
        cli,
        "find_bike_advertisement_by_address",
        AsyncMock(return_value=(MagicMock(), MagicMock(), advertisement)),
    )
    fake = _FakeCloud()
    monkeypatch.setattr(cloud_module, "SpecializedCloudClient", lambda: fake)
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "secret")

    await cli._cmd_fetch_key(
        _args(
            address="AA:BB:CC:DD:EE:FF",
            hmi_hardware="9.9.9",
            hmi_serial=None,
        )
    )

    assert fake.key_args == ("9.9.9", "987654321")


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (
            _args(hmi_hardware=None, hmi_serial=None),
            "provide a BLE address",
        ),
        (
            _args(
                address="AA:BB:CC:DD:EE:FF",
                hmi_hardware=None,
                hmi_serial=None,
            ),
            "could not find Specialized bike",
        ),
    ],
)
async def test_fetch_key_lookup_errors(
    monkeypatch: pytest.MonkeyPatch,
    args: argparse.Namespace,
    message: str,
) -> None:
    monkeypatch.setattr(
        cli,
        "find_bike_advertisement_by_address",
        AsyncMock(return_value=None),
    )

    with pytest.raises(cli.CLICommandError, match=message):
        await cli._cmd_fetch_key(args)


async def test_fetch_key_rejects_legacy_advertisement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    advertisement = BikeAdvertisement(generation=BLEProfile.TCX)
    monkeypatch.setattr(
        cli,
        "find_bike_advertisement_by_address",
        AsyncMock(return_value=(MagicMock(), MagicMock(), advertisement)),
    )

    with pytest.raises(cli.CLICommandError, match="does not advertise"):
        await cli._cmd_fetch_key(
            _args(
                address="AA:BB:CC:DD:EE:FF",
                hmi_hardware=None,
                hmi_serial=None,
            )
        )


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (
            CloudAuthenticationError("bad credentials"),
            "authentication failed",
        ),
        (
            CloudRequestError("response contained secret"),
            "key retrieval failed",
        ),
    ],
)
async def test_fetch_key_cloud_errors_are_secret_safe(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    message: str,
) -> None:
    fake = _FakeCloud(error=error)
    monkeypatch.setattr(cloud_module, "SpecializedCloudClient", lambda: fake)
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "secret-password")

    with pytest.raises(cli.CLICommandError, match=message) as raised:
        await cli._cmd_fetch_key(_args())

    assert "secret-password" not in str(raised.value)
    assert "response contained secret" not in str(raised.value)
    assert fake.closed


def test_main_prints_command_errors_to_stderr(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def fail(_args: argparse.Namespace) -> None:
        raise cli.CLICommandError("safe failure")

    monkeypatch.setattr(cli, "_cmd_fetch_key", fail)

    with pytest.raises(SystemExit) as raised:
        cli.main(
            [
                "fetch-key",
                "--email",
                "rider@example.com",
                "--hmi-hardware",
                "3.2.1",
                "--hmi-serial",
                "123456789",
            ]
        )

    assert raised.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: safe failure\n"
