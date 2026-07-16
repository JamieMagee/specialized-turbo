"""
Tests for specialized_turbo.cli.

Covers: key-file read (validation, HMI binding, permission warning, size
bound), bike/BikeInfo resolution (not-found, incomplete/Apple-only, TCU1
bypass), no-inline-key/no-fetch-key CLI flags, and the TCX/TCU1
read/write/telemetry/capture command paths. No real BLE or network
traffic is used anywhere.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

import pytest

import specialized_turbo.cli as cli
from specialized_turbo.bike_info import BikeInfo, HmiType, ProtocolEncryptionMethod
from specialized_turbo.identification import WireMessage
from specialized_turbo.keystore.models import BikeEncryptionKey
from specialized_turbo.parameters import BikeParameter
from specialized_turbo.protocol import BLEProfile, ParsedMessage
from specialized_turbo.wire_profiles import TCXGeneration

RAW_KEY_HEX = "00112233445566778899aabbccddeeff"[:32]
RAW_KEY = bytes.fromhex(RAW_KEY_HEX)
HMI_HW = "B.4.3"  # valid TCU2-category hardware version (see _hmi_compat_data)
HMI_SN = "1234"


def _nordic_payload(
    hmi_sn: str = HMI_SN, bike_type: int = 3, system_state: int = 1
) -> bytes:
    """Build a valid 10-byte Nordic advertisement record for HMI_HW/HMI_SN."""
    serial = int(hmi_sn).to_bytes(4, "little")
    hw = HMI_HW.replace(".", "").encode("latin-1")
    assert len(hw) == 3
    return serial + hw + b"\x00" + bytes([bike_type, system_state])


def _tcx_bike_info(*, hmi_hw: str = HMI_HW, hmi_sn: str = HMI_SN) -> BikeInfo:
    return BikeInfo(
        name="SPECIALIZED",
        bike_name="LEVO2 SPECIALIZED",
        is_bike=True,
        complete=True,
        hmi_serial=hmi_sn,
        hmi_hardware_version=hmi_hw,
        hmi_type=HmiType.TCU2,
        ble_profile=BLEProfile.TCX,
        tcx_generation=TCXGeneration.TCX2,
        encryption_method=ProtocolEncryptionMethod.AES_CTR,
    )


def _tcu1_bike_info() -> BikeInfo:
    return BikeInfo(
        name="SPECIALIZED",
        bike_name="TURBO SPECIALIZED",
        is_bike=True,
        complete=True,
        hmi_type=HmiType.TCU1,
        ble_profile=BLEProfile.TCU1,
        tcx_generation=None,
        encryption_method=ProtocolEncryptionMethod.NONE,
    )


def _incomplete_bike_info() -> BikeInfo:
    return BikeInfo(
        name="SPECIALIZED",
        bike_name="SPECIALIZED",
        is_bike=True,
        complete=False,
        ble_profile=BLEProfile.TCX,
    )


def _not_bike_info() -> BikeInfo:
    return BikeInfo(
        name="Random Device", bike_name="Random Device", is_bike=False, complete=False
    )


def _namespace(**kwargs: Any) -> argparse.Namespace:
    defaults = {"key_file": None}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# Key file: read (validation, HMI binding, permission warning)
# ---------------------------------------------------------------------------


class TestReadKeyFile:
    def _write_valid(
        self, path, hmi_hw=HMI_HW, hmi_sn=HMI_SN, key_hex=RAW_KEY_HEX, version=1
    ):
        payload = {
            "version": version,
            "hmi_hw": hmi_hw,
            "hmi_sn": hmi_sn,
            "key": key_hex,
        }
        path.write_text(json.dumps(payload))

    def test_read_valid_file_returns_matching_key(self, tmp_path):
        path = tmp_path / "key.json"
        self._write_valid(path)

        key = cli._read_key_file(str(path), _tcx_bike_info())

        assert isinstance(key, BikeEncryptionKey)
        assert key.raw == RAW_KEY

    def test_read_missing_file_raises(self, tmp_path):
        with pytest.raises(cli.KeyFileError, match="not found"):
            cli._read_key_file(str(tmp_path / "missing.json"), _tcx_bike_info())

    def test_read_invalid_json_raises(self, tmp_path):
        path = tmp_path / "key.json"
        path.write_text("{ not json")

        with pytest.raises(cli.KeyFileError, match="not valid JSON"):
            cli._read_key_file(str(path), _tcx_bike_info())

    def test_read_non_object_json_raises(self, tmp_path):
        path = tmp_path / "key.json"
        path.write_text("[1, 2, 3]")

        with pytest.raises(cli.KeyFileError, match="JSON object"):
            cli._read_key_file(str(path), _tcx_bike_info())

    def test_read_wrong_version_raises(self, tmp_path):
        path = tmp_path / "key.json"
        self._write_valid(path, version=2)

        with pytest.raises(cli.KeyFileError, match="version"):
            cli._read_key_file(str(path), _tcx_bike_info())

    @pytest.mark.parametrize("missing_field", ["hmi_hw", "hmi_sn", "key"])
    def test_read_missing_field_raises(self, tmp_path, missing_field):
        path = tmp_path / "key.json"
        payload = {"version": 1, "hmi_hw": HMI_HW, "hmi_sn": HMI_SN, "key": RAW_KEY_HEX}
        del payload[missing_field]
        path.write_text(json.dumps(payload))

        with pytest.raises(cli.KeyFileError, match="missing required fields"):
            cli._read_key_file(str(path), _tcx_bike_info())

    def test_read_hmi_hw_mismatch_raises(self, tmp_path):
        path = tmp_path / "key.json"
        self._write_valid(path, hmi_hw="X.1.1")

        with pytest.raises(cli.KeyFileError, match="wrong bike"):
            cli._read_key_file(str(path), _tcx_bike_info())

    def test_read_hmi_sn_mismatch_raises(self, tmp_path):
        path = tmp_path / "key.json"
        self._write_valid(path, hmi_sn="9999")

        with pytest.raises(cli.KeyFileError, match="wrong bike"):
            cli._read_key_file(str(path), _tcx_bike_info())

    def test_read_non_hex_key_raises(self, tmp_path):
        path = tmp_path / "key.json"
        self._write_valid(path, key_hex="not-hex-not-hex-not-hex-not-hex")

        with pytest.raises(cli.KeyFileError, match="lowercase hex"):
            cli._read_key_file(str(path), _tcx_bike_info())

    def test_read_uppercase_hex_key_rejected(self, tmp_path):
        path = tmp_path / "key.json"
        self._write_valid(path, key_hex=RAW_KEY_HEX.upper())

        with pytest.raises(cli.KeyFileError, match="lowercase hex"):
            cli._read_key_file(str(path), _tcx_bike_info())

    def test_read_short_key_raises(self, tmp_path):
        path = tmp_path / "key.json"
        self._write_valid(path, key_hex="aabb")

        with pytest.raises(cli.KeyFileError):
            cli._read_key_file(str(path), _tcx_bike_info())

    def test_read_never_prints_key(self, tmp_path, capsys):
        path = tmp_path / "key.json"
        self._write_valid(path)

        cli._read_key_file(str(path), _tcx_bike_info())

        captured = capsys.readouterr()
        assert RAW_KEY_HEX not in captured.out
        assert RAW_KEY_HEX not in captured.err

    @pytest.mark.skipif(os.name != "posix", reason="POSIX file mode only")
    def test_read_warns_on_permissive_mode(self, tmp_path, capsys):
        path = tmp_path / "key.json"
        self._write_valid(path)
        os.chmod(path, 0o644)

        cli._read_key_file(str(path), _tcx_bike_info())

        captured = capsys.readouterr()
        assert "Warning" in captured.err
        assert str(path) in captured.err

    @pytest.mark.skipif(os.name != "posix", reason="POSIX file mode only")
    def test_read_does_not_warn_on_0600(self, tmp_path, capsys):
        path = tmp_path / "key.json"
        self._write_valid(path)
        os.chmod(path, 0o600)

        cli._read_key_file(str(path), _tcx_bike_info())

        captured = capsys.readouterr()
        assert "Warning" not in captured.err

    def test_read_rejects_oversized_file(self, tmp_path):
        path = tmp_path / "key.json"
        # Valid JSON shape, but padded with a huge extra field so the file
        # itself exceeds the bound -- must be rejected outright.
        payload = {
            "version": 1,
            "hmi_hw": HMI_HW,
            "hmi_sn": HMI_SN,
            "key": RAW_KEY_HEX,
            "padding": "x" * (cli._MAX_KEY_FILE_BYTES + 1024),
        }
        path.write_text(json.dumps(payload))
        assert path.stat().st_size > cli._MAX_KEY_FILE_BYTES

        with pytest.raises(cli.KeyFileError, match="exceeds"):
            cli._read_key_file(str(path), _tcx_bike_info())

    def test_read_oversized_file_error_does_not_echo_content(self, tmp_path):
        path = tmp_path / "key.json"
        marker = "SENTINEL-" + "y" * cli._MAX_KEY_FILE_BYTES
        path.write_text(marker)

        with pytest.raises(cli.KeyFileError) as excinfo:
            cli._read_key_file(str(path), _tcx_bike_info())

        assert marker not in str(excinfo.value)
        assert "SENTINEL" not in str(excinfo.value)

    def test_read_at_exactly_the_limit_is_accepted(self, tmp_path):
        # A file whose content is *exactly* the bound (padded via JSON
        # whitespace) must still be read normally -- only content
        # strictly larger than the bound is rejected.
        path = tmp_path / "key.json"
        payload = {
            "version": 1,
            "hmi_hw": HMI_HW,
            "hmi_sn": HMI_SN,
            "key": RAW_KEY_HEX,
        }
        body = json.dumps(payload)
        padded = body + " " * (cli._MAX_KEY_FILE_BYTES - len(body.encode("utf-8")))
        assert len(padded.encode("utf-8")) == cli._MAX_KEY_FILE_BYTES
        path.write_text(padded)

        key = cli._read_key_file(str(path), _tcx_bike_info())
        assert key.raw == RAW_KEY


# ---------------------------------------------------------------------------
# _resolve_bike_info
# ---------------------------------------------------------------------------


class TestResolveBikeInfo:
    @pytest.mark.asyncio
    async def test_not_found_raises(self, monkeypatch):
        async def _fake_find(address, timeout):
            return None

        monkeypatch.setattr(cli, "find_advertisement_by_address", _fake_find)

        with pytest.raises(cli.BikeNotFoundError, match="No advertisement"):
            await cli._resolve_bike_info("AA:BB:CC:DD:EE:FF", 5.0)

    @pytest.mark.asyncio
    async def test_tcu1_bypasses_completeness_check(self, monkeypatch):
        device = argparse.Namespace(name="SPECIALIZED", address="AA:BB:CC:DD:EE:FF")
        adv = argparse.Namespace(manufacturer_data={0x020D: b"\x01"})

        async def _fake_find(address, timeout):
            return device, adv

        monkeypatch.setattr(cli, "find_advertisement_by_address", _fake_find)

        info = await cli._resolve_bike_info("AA:BB:CC:DD:EE:FF", 5.0)
        assert info.ble_profile == BLEProfile.TCU1
        assert info.complete is True

    @pytest.mark.asyncio
    async def test_complete_tcx_bike_returned(self, monkeypatch):
        device = argparse.Namespace(name="SPECIALIZED", address="AA:BB:CC:DD:EE:FF")
        adv = argparse.Namespace(manufacturer_data={0x0059: _nordic_payload()})

        async def _fake_find(address, timeout):
            return device, adv

        monkeypatch.setattr(cli, "find_advertisement_by_address", _fake_find)

        info = await cli._resolve_bike_info("AA:BB:CC:DD:EE:FF", 5.0)
        assert info.ble_profile == BLEProfile.TCX
        assert info.complete is True
        assert info.hmi_serial == HMI_SN

    @pytest.mark.asyncio
    async def test_incomplete_apple_only_raises_clear_retry_error(self, monkeypatch):
        # Detected as a bike by name, but only Apple iBeacon manufacturer
        # data is present -- no Nordic 10-byte structured record, so the
        # result is is_bike=True, complete=False.
        device = argparse.Namespace(name="SPECIALIZED", address="AA:BB:CC:DD:EE:FF")
        adv = argparse.Namespace(
            manufacturer_data={0x004C: b"\x02\x15" + b"TURBOHMI2017"[:12]}
        )

        async def _fake_find(address, timeout):
            return device, adv

        monkeypatch.setattr(cli, "find_advertisement_by_address", _fake_find)

        with pytest.raises(cli.BikeInfoIncompleteError, match="Move closer"):
            await cli._resolve_bike_info("AA:BB:CC:DD:EE:FF", 5.0)

    @pytest.mark.asyncio
    async def test_unrecognized_device_raises(self, monkeypatch):
        device = argparse.Namespace(name="Random Device", address="AA:BB:CC:DD:EE:FF")
        adv = argparse.Namespace(manufacturer_data={})

        async def _fake_find(address, timeout):
            return device, adv

        monkeypatch.setattr(cli, "find_advertisement_by_address", _fake_find)

        with pytest.raises(cli.BikeInfoIncompleteError, match="does not look like"):
            await cli._resolve_bike_info("AA:BB:CC:DD:EE:FF", 5.0)


# ---------------------------------------------------------------------------
# _resolve_key
# ---------------------------------------------------------------------------


class TestResolveKey:
    @pytest.mark.asyncio
    async def test_tcu1_bypasses_key(self):
        key = await cli._resolve_key(_tcu1_bike_info(), _namespace())
        assert key is None

    @pytest.mark.asyncio
    async def test_key_file_used_when_given(self, tmp_path):
        path = tmp_path / "key.json"
        payload = {"version": 1, "hmi_hw": HMI_HW, "hmi_sn": HMI_SN, "key": RAW_KEY_HEX}
        path.write_text(json.dumps(payload))

        key = await cli._resolve_key(_tcx_bike_info(), _namespace(key_file=str(path)))

        assert key is not None
        assert key.raw == RAW_KEY

    @pytest.mark.asyncio
    async def test_neither_given_raises(self):
        with pytest.raises(cli.KeyRequiredError, match="--key-file"):
            await cli._resolve_key(_tcx_bike_info(), _namespace())


# ---------------------------------------------------------------------------
# argparse: no inline --key flag, no --fetch-key/fetch-key backend command
# ---------------------------------------------------------------------------


class TestArgparse:
    def test_no_inline_key_flag_exists(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["telemetry", "AA:BB:CC:DD:EE:FF", "--key", "deadbeef"])
        captured = capsys.readouterr()
        assert "unrecognized" in captured.err

    def test_no_fetch_key_flag_exists(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["telemetry", "AA:BB:CC:DD:EE:FF", "--fetch-key"])
        captured = capsys.readouterr()
        assert "unrecognized" in captured.err

    def test_no_fetch_key_command_exists(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["fetch-key", "AA:BB:CC:DD:EE:FF"])
        captured = capsys.readouterr()
        assert "invalid choice" in captured.err


# ---------------------------------------------------------------------------
# scan: prints a safe BikeInfo summary
# ---------------------------------------------------------------------------


class TestCmdScan:
    @pytest.mark.asyncio
    async def test_scan_prints_bikeinfo_summary(self, monkeypatch, capsys):
        device = argparse.Namespace(name="SPECIALIZED", address="AA:BB:CC:DD:EE:FF")
        adv = argparse.Namespace(
            manufacturer_data={0x0059: _nordic_payload()}, rssi=-55
        )

        async def _fake_scan(timeout):
            return [(device, adv)]

        monkeypatch.setattr(cli, "scan_for_bikes", _fake_scan)

        await cli._cmd_scan(argparse.Namespace(timeout=5.0))

        out = capsys.readouterr().out
        assert "AA:BB:CC:DD:EE:FF" in out
        assert "Profile:" in out
        assert "HMI HW:" in out
        assert "HMI serial:" in out
        # Never any key/credential material -- BikeInfo carries none.
        assert "key" not in out.lower()
        assert "password" not in out.lower()


# ---------------------------------------------------------------------------
# read/write/telemetry/capture: TCX + TCU1 command paths
# ---------------------------------------------------------------------------


class _FakeConnection:
    """Stand-in for SpecializedConnection used by connection-establishing commands."""

    instances: list[_FakeConnection] = []

    def __init__(
        self,
        address,
        *,
        pin=None,
        generation: BLEProfile | None = None,
        bike_info: BikeInfo | None = None,
        key: BikeEncryptionKey | None = None,
        trace_callback=None,
        **kwargs,
    ):
        self.address = address
        self.pin = pin
        self.generation = generation
        self.bike_info = bike_info
        self.key = key
        self.trace_callback = trace_callback
        self.tcx_responses: dict[BikeParameter, WireMessage] = {}
        self.tcu1_responses: dict[tuple[int, int], ParsedMessage] = {}
        self.written_tcx: list[tuple[BikeParameter, bytes]] = []
        self.written_tcu1: list[bytes] = []
        _FakeConnection.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def request_tcx_parameter(self, param, *, timeout=None):
        return self.tcx_responses[param]

    async def write_tcx_parameter(self, param, data):
        self.written_tcx.append((param, bytes(data)))

    async def request_value(self, sender, channel):
        return self.tcu1_responses[(sender, channel)]

    async def write_command(self, data):
        self.written_tcu1.append(bytes(data))

    async def subscribe_notifications(self, callback):
        pass

    async def unsubscribe_notifications(self):
        pass


@pytest.fixture
def fake_connection(monkeypatch):
    _FakeConnection.instances = []
    monkeypatch.setattr(cli, "SpecializedConnection", _FakeConnection)
    return _FakeConnection


@pytest.fixture
def resolved_tcx_bike(monkeypatch):
    async def _fake_resolve(address, timeout):
        return _tcx_bike_info()

    monkeypatch.setattr(cli, "_resolve_bike_info", _fake_resolve)


@pytest.fixture
def resolved_tcu1_bike(monkeypatch):
    async def _fake_resolve(address, timeout):
        return _tcu1_bike_info()

    monkeypatch.setattr(cli, "_resolve_bike_info", _fake_resolve)


@pytest.fixture
def ephemeral_key(monkeypatch):
    async def _fake_key(bike_info, args):
        if bike_info.ble_profile == BLEProfile.TCU1:
            return None
        return BikeEncryptionKey(raw=RAW_KEY)

    monkeypatch.setattr(cli, "_resolve_key", _fake_key)


class TestCmdReadTCX:
    @pytest.mark.asyncio
    async def test_reads_tcx_field(
        self, fake_connection, resolved_tcx_bike, ephemeral_key, capsys, monkeypatch
    ):
        param = cli._TCX_FIELD_NAME_MAP["battery_charge_percent"]
        param_enum = BikeParameter(param)

        # Patch request_tcx_parameter response after connection is created:
        # use a subclass hook via instances list post-hoc is awkward, so
        # pre-seed via a connection factory closure instead.
        def _factory(address, **kwargs):
            conn = _FakeConnection(address, **kwargs)
            conn.tcx_responses[param_enum] = WireMessage(
                wire_id=0x1234,
                parameter=param_enum,
                data=b"\x32",
                value=50,
                nak_reason=None,
            )
            return conn

        monkeypatch.setattr(cli, "SpecializedConnection", _factory)

        args = argparse.Namespace(
            field="battery_charge_percent",
            address="AA:BB:CC:DD:EE:FF",
            pin=None,
            format="table",
            key_file=None,
            scan_timeout=5.0,
        )
        await cli._cmd_read(args)

        out = capsys.readouterr().out
        assert "battery_charge_percent = 50 %" in out

    @pytest.mark.asyncio
    async def test_reads_tcx_field_nak(
        self, fake_connection, resolved_tcx_bike, ephemeral_key, capsys, monkeypatch
    ):
        param = cli._TCX_FIELD_NAME_MAP["battery_charge_percent"]
        param_enum = BikeParameter(param)

        def _factory(address, **kwargs):
            conn = _FakeConnection(address, **kwargs)
            conn.tcx_responses[param_enum] = WireMessage(
                wire_id=0x1234,
                parameter=param_enum,
                data=b"",
                value=None,
                nak_reason=0x02,
            )
            return conn

        monkeypatch.setattr(cli, "SpecializedConnection", _factory)

        args = argparse.Namespace(
            field="battery_charge_percent",
            address="AA:BB:CC:DD:EE:FF",
            pin=None,
            format="table",
            key_file=None,
            scan_timeout=5.0,
        )
        await cli._cmd_read(args)

        out = capsys.readouterr().out
        assert "rejected" in out

    @pytest.mark.asyncio
    async def test_read_requires_key_file(self, fake_connection, resolved_tcx_bike):
        args = argparse.Namespace(
            field="battery_charge_percent",
            address="AA:BB:CC:DD:EE:FF",
            pin=None,
            format="table",
            key_file=None,
            scan_timeout=5.0,
        )
        with pytest.raises(cli.KeyRequiredError):
            await cli._cmd_read(args)

    @pytest.mark.asyncio
    async def test_tcu1_field_on_tcx_bike_is_rejected(
        self, fake_connection, resolved_tcx_bike, ephemeral_key, capsys
    ):
        args = argparse.Namespace(
            field="shuttle",
            address="AA:BB:CC:DD:EE:FF",
            pin=None,
            format="table",
            key_file=None,
            scan_timeout=5.0,
        )
        with pytest.raises(SystemExit):
            await cli._cmd_read(args)
        out = capsys.readouterr().out
        assert "not available on this bike's protocol" in out


class TestCmdReadTCU1:
    @pytest.mark.asyncio
    async def test_reads_tcu1_field(
        self, fake_connection, resolved_tcu1_bike, ephemeral_key, capsys, monkeypatch
    ):
        def _factory(address, **kwargs):
            conn = _FakeConnection(address, **kwargs)
            conn.tcu1_responses[(0x01, 0x00)] = ParsedMessage(
                sender=0x01,
                channel=0x00,
                raw_value=42,
                converted_value=42,
                field_name="rider_power",
                unit="W",
            )
            return conn

        monkeypatch.setattr(cli, "SpecializedConnection", _factory)

        args = argparse.Namespace(
            field="rider_power",
            address="AA:BB:CC:DD:EE:FF",
            pin=None,
            format="table",
            key_file=None,
            scan_timeout=5.0,
        )
        await cli._cmd_read(args)

        out = capsys.readouterr().out
        assert "rider_power = 42 W" in out

    @pytest.mark.asyncio
    async def test_tcx_only_field_on_tcu1_bike_is_rejected(
        self, fake_connection, resolved_tcu1_bike, ephemeral_key, capsys
    ):
        args = argparse.Namespace(
            field="max_speed_limit",
            address="AA:BB:CC:DD:EE:FF",
            pin=None,
            format="table",
            key_file=None,
            scan_timeout=5.0,
        )
        with pytest.raises(SystemExit):
            await cli._cmd_read(args)
        out = capsys.readouterr().out
        assert "not available on this bike's protocol" in out


class TestCmdWrite:
    @pytest.mark.asyncio
    async def test_writes_tcx_field(
        self, fake_connection, resolved_tcx_bike, ephemeral_key
    ):
        args = argparse.Namespace(
            field="assist_level",
            value="2",
            address="AA:BB:CC:DD:EE:FF",
            pin=None,
            key_file=None,
            scan_timeout=5.0,
        )
        await cli._cmd_write(args)

        conn = _FakeConnection.instances[-1]
        assert conn.written_tcx == [(BikeParameter.MOTOR_ACTIVE_TRAVEL_MODE, b"\x02")]

    @pytest.mark.asyncio
    async def test_writes_tcu1_field(
        self, fake_connection, resolved_tcu1_bike, ephemeral_key
    ):
        args = argparse.Namespace(
            field="shuttle",
            value="50",
            address="AA:BB:CC:DD:EE:FF",
            pin=None,
            key_file=None,
            scan_timeout=5.0,
        )
        await cli._cmd_write(args)

        conn = _FakeConnection.instances[-1]
        assert len(conn.written_tcu1) == 1


class TestCmdTelemetry:
    @pytest.mark.asyncio
    async def test_telemetry_forwards_generation_bike_info_key(
        self, resolved_tcx_bike, ephemeral_key, monkeypatch
    ):
        captured = {}

        async def _fake_run_telemetry_session(address, **kwargs):
            captured.update(kwargs)
            captured["address"] = address
            from specialized_turbo.models import TelemetrySnapshot

            return TelemetrySnapshot()

        monkeypatch.setattr(cli, "run_telemetry_session", _fake_run_telemetry_session)

        args = argparse.Namespace(
            address="AA:BB:CC:DD:EE:FF",
            pin=None,
            duration=0,
            format="table",
            key_file=None,
            scan_timeout=5.0,
        )
        await cli._cmd_telemetry(args)

        assert captured["generation"] == BLEProfile.TCX
        assert captured["bike_info"].hmi_serial == HMI_SN
        assert captured["key"].raw == RAW_KEY


class TestCmdCapture:
    @pytest.mark.asyncio
    async def test_capture_forwards_generation_bike_info_key(
        self, fake_connection, resolved_tcx_bike, ephemeral_key
    ):
        args = argparse.Namespace(
            address="AA:BB:CC:DD:EE:FF",
            pin=None,
            duration=0.01,
            key_file=None,
            scan_timeout=5.0,
        )
        await cli._cmd_capture(args)

        conn = _FakeConnection.instances[-1]
        assert conn.generation == BLEProfile.TCX
        assert conn.bike_info is not None
        assert conn.bike_info.hmi_serial == HMI_SN
        assert conn.key is not None
        assert conn.key.raw == RAW_KEY

    @pytest.mark.asyncio
    async def test_capture_tcu1_bypasses_key(
        self, fake_connection, resolved_tcu1_bike, ephemeral_key
    ):
        args = argparse.Namespace(
            address="AA:BB:CC:DD:EE:FF",
            pin=None,
            duration=0.01,
            key_file=None,
            scan_timeout=5.0,
        )
        await cli._cmd_capture(args)

        conn = _FakeConnection.instances[-1]
        assert conn.generation == BLEProfile.TCU1
        assert conn.key is None
