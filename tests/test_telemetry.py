"""
Unit tests for ``TelemetryMonitor``'s profile-aware notification handling and
unified connection polling.

A duck-typed fake stands in for ``SpecializedConnection``. Two fake
connection variants exercise both sides of
``TelemetryMonitor._active_revision``'s narrow, type-validated lookup:

- one with no ``active_revision`` attribute at all -- notifications fall
  back to the legacy, non-profile-aware parse and polling is skipped.
- one that implements :class:`~specialized_turbo.telemetry
  .RevisionAwareConnection` (as the real ``SpecializedConnection`` now does)
  -- notifications are parsed profile-aware and ``poll_telemetry`` updates the
  monitor snapshot.

The fake's ``request_tcx_value`` deliberately raises: priming (and every
other live path) must never fall back to the deprecated raw enum-id call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar, Self, cast

import pytest
from bleak.backends.characteristic import BleakGATTCharacteristic

import specialized_turbo.telemetry as telemetry_module
from specialized_turbo.bike_info import BikeInfo
from specialized_turbo.connection import SpecializedConnection
from specialized_turbo.coordinator_helpers import TCX_POLL_PARAMS
from specialized_turbo.identification import WireMessage
from specialized_turbo.key_provider import EncryptionKeyProvider
from specialized_turbo.keystore.models import BikeEncryptionKey
from specialized_turbo.parameters import BikeParameter, encode_parameter_id
from specialized_turbo.protocol import BatteryChannel, BLEProfile, ParsedMessage, Sender
from specialized_turbo.session import ProtocolSession, TCU1Session, TCXSession
from specialized_turbo.telemetry import (
    RevisionAwareConnection,
    TelemetryMonitor,
    run_telemetry_session,
)
from specialized_turbo.transport import NotificationCallback, TCXRequestTimeoutError
from specialized_turbo.wire_profiles import (
    ProtocolRevision,
    TCXGeneration,
    UnmappedParameterError,
)

KEY_RAW = b"\x11" * 16
IV = b"\x22" * 16

SOC_WIRE_ID = 0x0500  # real wire id for BATTERY1_STATE_OF_CHARGE (26)
GENERATION = TCXGeneration.TCX2
REVISION = 0x12


@dataclass
class _FakeCharacteristic:
    uuid: str


_CHARACTERISTIC = cast(BleakGATTCharacteristic, _FakeCharacteristic("fake"))


@dataclass
class _FakeConnection:
    """Duck-typed stand-in exposing only what ``TelemetryMonitor`` needs."""

    session: ProtocolSession
    requested_params: list[BikeParameter] = field(default_factory=list)
    timeout_after: int | None = None
    unmapped: set[BikeParameter] = field(default_factory=set)
    _callback: NotificationCallback | None = field(default=None, init=False)

    async def subscribe_notifications(self, callback: NotificationCallback) -> None:
        self._callback = callback

    async def unsubscribe_notifications(self) -> None:
        self._callback = None

    async def request_tcx_parameter(
        self, param: BikeParameter, *, timeout: float | None = None
    ) -> WireMessage:
        """Profile-aware read used by ``_prime_tcx_snapshot``."""
        if param in self.unmapped:
            raise UnmappedParameterError(param.name)
        self.requested_params.append(param)
        if self.timeout_after is not None and len(self.requested_params) > (
            self.timeout_after
        ):
            raise TCXRequestTimeoutError(int(param), 0.001)
        return WireMessage(wire_id=int(param), parameter=param, data=b"", value=None)

    async def request_tcx_value(self, param_id: int) -> ParsedMessage:
        """Deprecated raw path -- must never be reached from live code."""
        raise AssertionError(
            "TelemetryMonitor must not use the deprecated raw request_tcx_value"
        )

    def notify(self, data: bytes) -> None:
        assert self._callback is not None
        self._callback(_CHARACTERISTIC, bytearray(data))


@dataclass
class _FakeRevisionAwareConnection(_FakeConnection):
    """Same as ``_FakeConnection`` but implements ``active_revision``."""

    revision: ProtocolRevision | None = None
    poll_calls: int = 0

    @property
    def active_revision(self) -> ProtocolRevision | None:
        return self.revision

    async def poll_telemetry(self, _snapshot: object) -> bool:
        """Simulate the connection's unified polling path."""
        self.poll_calls += 1
        for param in TCX_POLL_PARAMS:
            if param in self.unmapped:
                continue
            self.requested_params.append(param)
            if self.timeout_after is not None and len(self.requested_params) > (
                self.timeout_after
            ):
                break
        return bool(self.requested_params)


def _revision() -> ProtocolRevision:
    return ProtocolRevision(generation=GENERATION, revision=REVISION)


# ---------------------------------------------------------------------------
# Legacy fallback when no revision is available (requirement 3)
# ---------------------------------------------------------------------------


class TestFallsBackWithoutRevision:
    async def test_plain_connection_has_no_active_revision(self) -> None:
        conn = _FakeConnection(session=TCXSession())
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))

        assert monitor._active_revision() is None

    async def test_legacy_parse_used_when_revision_unknown(self) -> None:
        """Without a revision, notifications parse via the legacy enum-ID path."""
        conn = _FakeConnection(session=TCXSession())
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))
        await monitor.start()

        # Legacy parse_tcx_message treats the wire header as the
        # BikeParameter enum value directly: 26 == BATTERY1_STATE_OF_CHARGE.
        legacy_wire = int(BikeParameter.BATTERY1_STATE_OF_CHARGE)
        packet = TCXSession().pack(encode_parameter_id(legacy_wire) + bytes([37]))
        conn.notify(packet)

        assert monitor.snapshot.battery.charge_pct == 37
        await monitor.stop()


# ---------------------------------------------------------------------------
# Profile-aware parse when a revision is available (requirements 1 & 3)
# ---------------------------------------------------------------------------


class TestProfileAwareWithRevision:
    async def test_uses_wire_id_for_active_revision(self) -> None:
        conn = _FakeRevisionAwareConnection(session=TCXSession(), revision=_revision())
        assert isinstance(conn, RevisionAwareConnection)
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))
        await monitor.start()

        # The real wire id (0x0500), not the BikeParameter enum id (26).
        packet = TCXSession().pack(encode_parameter_id(SOC_WIRE_ID) + bytes([61]))
        conn.notify(packet)

        assert monitor.snapshot.battery.charge_pct == 61
        await monitor.stop()

    async def test_legacy_wire_id_no_longer_resolves_once_profile_aware(self) -> None:
        """0x001a isn't a real TCX2 wire id; profile-aware parsing leaves it unknown."""
        conn = _FakeRevisionAwareConnection(session=TCXSession(), revision=_revision())
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))
        await monitor.start()

        legacy_wire = int(BikeParameter.BATTERY1_STATE_OF_CHARGE)
        packet = TCXSession().pack(encode_parameter_id(legacy_wire) + bytes([37]))
        conn.notify(packet)

        assert monitor.snapshot.battery.charge_pct is None
        await monitor.stop()

    async def test_encrypted_session_notification_decrypts_and_parses(self) -> None:
        session = TCXSession(key=KEY_RAW, iv=IV)
        conn = _FakeRevisionAwareConnection(session=session, revision=_revision())
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))
        await monitor.start()

        packet = session.pack(encode_parameter_id(SOC_WIRE_ID) + bytes([88]))
        conn.notify(packet)

        assert monitor.snapshot.battery.charge_pct == 88
        await monitor.stop()

    async def test_nak_increments_count_without_updating_snapshot(self) -> None:
        conn = _FakeRevisionAwareConnection(session=TCXSession(), revision=_revision())
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))
        await monitor.start()

        nak = b"\xf8\xff" + encode_parameter_id(SOC_WIRE_ID) + bytes([0x05])
        conn.notify(TCXSession().pack(nak))

        assert monitor.nak_count == 1
        assert monitor.snapshot.battery.charge_pct is None
        await monitor.stop()

    async def test_realtime_bundle_still_suppressed_regardless_of_revision(
        self,
    ) -> None:
        """f8f4 bundles are explicitly suppressed, not misparsed (requirement 4)."""
        conn = _FakeRevisionAwareConnection(session=TCXSession(), revision=_revision())
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))
        await monitor.start()

        before = monitor.snapshot.message_count
        conn.notify(TCXSession().pack(b"\xf8\xf4" + bytes(16)))

        assert monitor.snapshot.message_count == before
        assert monitor.nak_count == 0
        await monitor.stop()


# ---------------------------------------------------------------------------
# Injectable revision accessor (requirement 3: alternative to the protocol)
# ---------------------------------------------------------------------------


class TestInjectableRevisionAccessor:
    async def test_accessor_takes_priority_over_connection_attribute(self) -> None:
        conn = _FakeConnection(session=TCXSession())  # no active_revision at all
        accessor_calls: list[int] = []

        def accessor() -> ProtocolRevision | None:
            accessor_calls.append(1)
            return _revision()

        monitor = TelemetryMonitor(
            cast(SpecializedConnection, conn), revision_accessor=accessor
        )

        assert monitor._active_revision() == _revision()
        assert accessor_calls == [1]

    async def test_accessor_returning_none_falls_back_to_legacy_parse(self) -> None:
        conn = _FakeRevisionAwareConnection(session=TCXSession(), revision=_revision())
        monitor = TelemetryMonitor(
            cast(SpecializedConnection, conn), revision_accessor=lambda: None
        )
        await monitor.start()

        legacy_wire = int(BikeParameter.BATTERY1_STATE_OF_CHARGE)
        packet = TCXSession().pack(encode_parameter_id(legacy_wire) + bytes([12]))
        conn.notify(packet)

        assert monitor.snapshot.battery.charge_pct == 12
        await monitor.stop()

    async def test_wrong_type_is_rejected_with_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A non-ProtocolRevision value is ignored, not passed to wire lookup."""
        conn = _FakeConnection(session=TCXSession())
        monitor = TelemetryMonitor(
            cast(SpecializedConnection, conn),
            revision_accessor=lambda: cast(ProtocolRevision, "not-a-revision"),
        )

        with caplog.at_level("WARNING"):
            assert monitor._active_revision() is None

        assert any("unexpected type" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Initial snapshot polling through the connection boundary
# ---------------------------------------------------------------------------


class TestUnifiedPolling:
    async def test_primes_every_poll_param_profile_aware(self) -> None:
        conn = _FakeRevisionAwareConnection(session=TCXSession(), revision=_revision())
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))

        await monitor.start()

        assert conn.requested_params == list(TCX_POLL_PARAMS)
        await monitor.stop()

    async def test_priming_stops_on_first_timeout(self) -> None:
        conn = _FakeRevisionAwareConnection(
            session=TCXSession(), revision=_revision(), timeout_after=2
        )
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))

        await monitor.start()

        assert len(conn.requested_params) == 3  # 2 ok + the one that times out
        await monitor.stop()

    async def test_unmapped_parameter_is_skipped_not_fatal(self) -> None:
        first = TCX_POLL_PARAMS[0]
        conn = _FakeRevisionAwareConnection(
            session=TCXSession(), revision=_revision(), unmapped={first}
        )
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))

        await monitor.start()

        assert first not in conn.requested_params
        assert conn.requested_params == [p for p in TCX_POLL_PARAMS if p != first]
        await monitor.stop()

    async def test_no_priming_without_revision(self) -> None:
        """Without a revision, priming is skipped -- never the raw enum path."""
        conn = _FakeConnection(session=TCXSession())  # no active_revision
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))

        await monitor.start()

        assert conn.requested_params == []
        await monitor.stop()

    async def test_start_invokes_connection_poll(self) -> None:
        conn = _FakeRevisionAwareConnection(session=TCXSession(), revision=_revision())
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))

        await monitor.start()

        assert conn.poll_calls == 1
        await monitor.poll()
        assert conn.poll_calls == 2
        await monitor.stop()


# ---------------------------------------------------------------------------
# TCU1 unchanged
# ---------------------------------------------------------------------------


class TestTcu1Unchanged:
    async def test_tcu1_notifications_use_the_legacy_sender_channel_parse(self) -> None:
        conn = _FakeConnection(session=TCU1Session())
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))
        await monitor.start()

        conn.notify(bytes([Sender.BATTERY, BatteryChannel.CHARGE_PERCENT, 55]))

        assert monitor.snapshot.battery.charge_pct == 55
        await monitor.stop()


# ---------------------------------------------------------------------------
# run_telemetry_session forwards generation / bike_info / key to the connection
# ---------------------------------------------------------------------------


class _RecordingConnection:
    """Fake SpecializedConnection that records its constructor kwargs."""

    captured: ClassVar[dict[str, object]] = {}

    def __init__(
        self,
        address: str,
        *,
        pin: str | None = None,
        generation: BLEProfile = BLEProfile.TCX,
        bike_info: BikeInfo | None = None,
        key: BikeEncryptionKey | None = None,
        key_provider: EncryptionKeyProvider | None = None,
        wrapped_key: str | None = None,
    ) -> None:
        type(self).captured = {
            "address": address,
            "pin": pin,
            "generation": generation,
            "bike_info": bike_info,
            "key": key,
            "key_provider": key_provider,
            "wrapped_key": wrapped_key,
        }
        self._session: ProtocolSession = (
            TCU1Session() if generation == BLEProfile.TCU1 else TCXSession()
        )

    @property
    def session(self) -> ProtocolSession:
        return self._session

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def subscribe_notifications(self, callback: NotificationCallback) -> None:
        return None

    async def unsubscribe_notifications(self) -> None:
        return None


class TestRunTelemetrySessionForwarding:
    async def test_forwards_tcu1_kwargs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            telemetry_module, "SpecializedConnection", _RecordingConnection
        )

        await run_telemetry_session(
            "AA:BB:CC:DD:EE:FF",
            pin="946166",
            generation=BLEProfile.TCU1,
            duration=0.001,
            output_callback=lambda _s: None,
        )

        assert _RecordingConnection.captured == {
            "address": "AA:BB:CC:DD:EE:FF",
            "pin": "946166",
            "generation": BLEProfile.TCU1,
            "bike_info": None,
            "key": None,
            "key_provider": None,
            "wrapped_key": None,
        }

    async def test_forwards_tcx_bike_info_and_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            telemetry_module, "SpecializedConnection", _RecordingConnection
        )
        info = BikeInfo(
            name="SPECIALIZED", bike_name="LEVO2", is_bike=True, complete=True
        )
        key = BikeEncryptionKey(raw=KEY_RAW)

        await run_telemetry_session(
            "AA:BB:CC:DD:EE:FF",
            pin="946166",
            generation=BLEProfile.TCX,
            bike_info=info,
            key=key,
            duration=0.001,
            output_callback=lambda _s: None,
        )

        captured = _RecordingConnection.captured
        assert captured["generation"] == BLEProfile.TCX
        assert captured["bike_info"] is info
        assert captured["key"] is key
        assert captured["pin"] == "946166"
