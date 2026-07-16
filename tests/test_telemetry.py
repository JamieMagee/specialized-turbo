"""
Unit tests for ``TelemetryMonitor``'s profile-aware TCX notification
handling.

A duck-typed fake stands in for ``SpecializedConnection`` (which this
module deliberately doesn't touch -- its identification/revision-negotiation
story is landing in parallel).  Two fake connection variants exercise both
sides of ``TelemetryMonitor._active_revision``'s narrow lookup:

- one with no ``active_revision`` attribute at all (today's
  ``SpecializedConnection``) -- notifications fall back to the legacy,
  non-profile-aware parse.
- one that implements :class:`~specialized_turbo.telemetry
  .RevisionAwareConnection` -- notifications are parsed profile-aware.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

import pytest
from bleak.backends.characteristic import BleakGATTCharacteristic

from specialized_turbo.connection import SpecializedConnection
from specialized_turbo.coordinator_helpers import TCX_POLL_PARAMS
from specialized_turbo.parameters import BikeParameter, encode_parameter_id
from specialized_turbo.protocol import BatteryChannel, ParsedMessage, Sender
from specialized_turbo.session import ProtocolSession, TCU1Session, TCXSession
from specialized_turbo.telemetry import RevisionAwareConnection, TelemetryMonitor
from specialized_turbo.transport import NotificationCallback, TCXRequestTimeoutError
from specialized_turbo.wire_profiles import ProtocolRevision, TCXGeneration

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
    requested_params: list[int] = field(default_factory=list)
    timeout_after: int | None = None
    _callback: NotificationCallback | None = field(default=None, init=False)

    async def subscribe_notifications(self, callback: NotificationCallback) -> None:
        self._callback = callback

    async def unsubscribe_notifications(self) -> None:
        self._callback = None

    async def request_tcx_value(self, param_id: int) -> ParsedMessage:
        self.requested_params.append(param_id)
        if self.timeout_after is not None and len(self.requested_params) > (
            self.timeout_after
        ):
            raise TCXRequestTimeoutError(param_id, 0.001)
        return ParsedMessage(
            sender=0,
            channel=0,
            raw_value=0,
            converted_value=None,
            field_name=None,
            unit="",
        )

    def notify(self, data: bytes) -> None:
        assert self._callback is not None
        self._callback(_CHARACTERISTIC, bytearray(data))


@dataclass
class _FakeRevisionAwareConnection(_FakeConnection):
    """Same as ``_FakeConnection`` but implements ``active_revision``."""

    revision: ProtocolRevision | None = None

    @property
    def active_revision(self) -> ProtocolRevision | None:
        return self.revision


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


# ---------------------------------------------------------------------------
# Initial snapshot priming (requirement 5)
# ---------------------------------------------------------------------------


class TestPrimeTcxSnapshot:
    async def test_primes_every_poll_param_through_legacy_request(self) -> None:
        conn = _FakeConnection(session=TCXSession())
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))

        await monitor.start()

        assert conn.requested_params == [int(p) for p in TCX_POLL_PARAMS]
        await monitor.stop()

    async def test_priming_stops_on_first_timeout(self) -> None:
        conn = _FakeConnection(session=TCXSession(), timeout_after=2)
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))

        await monitor.start()

        assert len(conn.requested_params) == 3  # 2 ok + the one that times out
        await monitor.stop()

    async def test_reports_priming_is_still_legacy_when_revision_known(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        conn = _FakeRevisionAwareConnection(session=TCXSession(), revision=_revision())
        monitor = TelemetryMonitor(cast(SpecializedConnection, conn))

        with caplog.at_level("INFO"):
            await monitor.start()

        assert any("priming is still legacy" in r.message for r in caplog.records)
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
