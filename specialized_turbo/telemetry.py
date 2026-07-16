"""
Telemetry monitoring for Specialized Turbo bikes.

Subscribes to BLE notifications, decodes them, and keeps a running
TelemetrySnapshot. Supports callbacks and async iteration.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Callable
from typing import Protocol, runtime_checkable

from bleak.backends.characteristic import BleakGATTCharacteristic

from .connection import SpecializedConnection
from .coordinator_helpers import TCX_POLL_PARAMS, parse_tcx_wire_payload
from .framing import is_realtime_packet
from .models import TelemetrySnapshot
from .protocol import parse_message, parse_tcx_message, ParsedMessage
from .session import TCXSession
from .transport import TCXRequestTimeoutError
from .wire_profiles import ProtocolRevision, UnmappedParameterError

logger = logging.getLogger(__name__)


@runtime_checkable
class RevisionAwareConnection(Protocol):
    """Narrow interface a connection exposes to advertise its negotiated
    TCX protocol revision.

    :class:`TelemetryMonitor` only needs this one read-only property to
    switch from the legacy enum-ID-assumption parse (:func:`~specialized_turbo
    .protocol.parse_tcx_message`) to profile-aware (:class:`ProtocolRevision`
    -> wire id) parsing of TCX notifications. Depending on this narrow
    structural protocol -- rather than importing a concrete connection
    type's identification internals -- keeps the telemetry layer decoupled
    from the connection layer. :class:`SpecializedConnection` satisfies it
    via its :attr:`~specialized_turbo.connection.SpecializedConnection.active_revision`
    property. A connection that doesn't implement it (or returns ``None``)
    is treated as "revision unknown" and notification parsing falls back to
    the legacy path; see :meth:`TelemetryMonitor._active_revision`.
    """

    @property
    def active_revision(self) -> ProtocolRevision | None: ...


class TelemetryMonitor:
    """
    Streams telemetry from a connected Specialized Turbo bike.

    Three ways to consume data:

    1. Read ``monitor.snapshot`` at any time for the latest state.
    2. Set ``monitor.on_update`` to a callback.
    3. Iterate with ``async for msg in monitor.stream():``

    Usage::

        async with SpecializedConnection(address, pin=pin) as conn:
            monitor = TelemetryMonitor(conn)
            await monitor.start()

            async for msg in monitor.stream():
                print(f"{msg.field_name} = {msg.converted_value} {msg.unit}")

            await monitor.stop()
    """

    def __init__(
        self,
        connection: SpecializedConnection,
        *,
        revision_accessor: Callable[[], ProtocolRevision | None] | None = None,
    ) -> None:
        self._conn = connection
        self._revision_accessor = revision_accessor
        self._snapshot = TelemetrySnapshot()
        self._running = False
        self._queue: asyncio.Queue[ParsedMessage | None] = asyncio.Queue()
        self._nak_count = 0
        self._reported_realtime_bundle = False
        self._reported_parse_mode = False
        self.on_update: Callable[[ParsedMessage, TelemetrySnapshot], None] | None = None
        """Optional callback invoked after each notification is processed."""

    @property
    def snapshot(self) -> TelemetrySnapshot:
        """Current aggregated telemetry state (updated in-place)."""
        return self._snapshot

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def nak_count(self) -> int:
        """Number of NAK (rejected) responses received since start."""
        return self._nak_count

    def _active_revision(self) -> ProtocolRevision | None:
        """Best-effort, type-validated lookup of the connection's negotiated revision.

        Prefers an injected ``revision_accessor`` (useful for tests, or for
        callers that don't want their connection type to implement
        :class:`RevisionAwareConnection` in full); otherwise reads
        ``connection.active_revision`` via ``getattr`` rather than an
        ``isinstance`` check, so this keeps working whether or not the
        connection type structurally satisfies the protocol.

        The result is validated: anything other than a
        :class:`ProtocolRevision` (or ``None``) is rejected with a warning
        and treated as "revision unknown", so a mistyped accessor or
        connection attribute can never smuggle a bogus object into the
        profile-aware wire-id resolution. ``None`` means notification parsing
        falls back to the legacy, non-profile-aware path.
        """
        if self._revision_accessor is not None:
            revision = self._revision_accessor()
        else:
            revision = getattr(self._conn, "active_revision", None)
        if revision is None or isinstance(revision, ProtocolRevision):
            return revision
        logger.warning(
            "Ignoring active_revision of unexpected type %s (expected "
            "ProtocolRevision or None); falling back to legacy parsing",
            type(revision).__name__,
        )
        return None

    async def start(self) -> None:
        """Subscribe to bike notifications and begin decoding."""
        if self._running:
            return
        self._running = True
        try:
            await self._conn.subscribe_notifications(self._notification_handler)
            if isinstance(self._conn.session, TCXSession):
                await self._prime_tcx_snapshot()
        except Exception:
            self._running = False
            await self._conn.unsubscribe_notifications()
            raise
        logger.info("TelemetryMonitor started")

    async def stop(self) -> None:
        """Unsubscribe from notifications."""
        if not self._running:
            return
        self._running = False
        await self._conn.unsubscribe_notifications()
        # Unblock any waiting stream consumers
        await self._queue.put(None)
        logger.info("TelemetryMonitor stopped")

    async def stream(self) -> AsyncIterator[ParsedMessage]:
        """
        Async generator yielding each parsed telemetry message as it arrives.

        The generator terminates when ``stop()`` is called.
        """
        while self._running:
            msg = await self._queue.get()
            if msg is None:
                break
            yield msg

    def _notification_handler(
        self, characteristic: BleakGATTCharacteristic, data: bytearray
    ) -> None:
        """Called by bleak for each notification. Parses, updates snapshot, notifies consumers."""
        try:
            session = self._conn.session
            unpacked = session.unpack(data)
            if isinstance(session, TCXSession):
                if is_realtime_packet(unpacked):
                    # f8f4 real-time bundles aren't decoded yet -- keep
                    # suppressing them explicitly rather than misparsing
                    # their payload as a single field.
                    if not self._reported_realtime_bundle:
                        logger.info(
                            "Receiving bundled TCX real-time data; "
                            "using notification-backed queries for snapshot values"
                        )
                        self._reported_realtime_bundle = True
                    return
                revision = self._active_revision()
                if revision is not None:
                    if not self._reported_parse_mode:
                        logger.info(
                            "Active TCX revision %s 0x%02x known; "
                            "parsing notifications profile-aware",
                            revision.generation.name,
                            revision.revision,
                        )
                        self._reported_parse_mode = True
                    msg = parse_tcx_wire_payload(unpacked, revision)
                else:
                    if not self._reported_parse_mode:
                        logger.info(
                            "No active TCX revision available from the "
                            "connection; parsing notifications with the "
                            "legacy enum-ID assumption"
                        )
                        self._reported_parse_mode = True
                    msg = parse_tcx_message(unpacked)
            else:
                msg = parse_message(unpacked)
        except Exception:
            logger.warning(
                "Failed to parse notification: %s", data.hex(), exc_info=True
            )
            return

        # NAK responses carry a rejection reason rather than data.  Don't
        # let them poison the snapshot or surface as fake telemetry to
        # consumers.
        if msg.nak_reason is not None:
            self._nak_count += 1
            logger.debug(
                "NAK notification: echoed_param=%d reason=0x%02x (nak_count=%d)",
                msg.raw_value,
                msg.nak_reason,
                self._nak_count,
            )
            return

        self._snapshot.update_from_message(msg)

        if msg.field_name:
            logger.debug(
                "%-28s = %8s %s",
                msg.field_name,
                msg.converted_value,
                msg.unit,
            )

        if self.on_update:
            try:
                self.on_update(msg, self._snapshot)
            except Exception:
                logger.warning("on_update callback raised", exc_info=True)

        self._queue.put_nowait(msg)

    async def _prime_tcx_snapshot(self) -> None:
        """Query the initial TCX values through the notification transport.

        Profile-aware: each :data:`TCX_POLL_PARAMS` entry is requested via
        :meth:`SpecializedConnection.request_tcx_parameter`, which resolves
        the app-level ``BikeParameter`` to a wire command id through the
        negotiated :class:`ProtocolRevision` -- the same revision the live
        ``_notification_handler`` uses to decode responses. The request and
        notification sides therefore switch together: when a revision is
        available both are profile-aware; when it is not, priming is skipped
        entirely (the deprecated raw enum-ID path is never used) and the
        snapshot is populated by live notifications alone.

        Per-parameter failures are contained: a parameter with no wire id
        for this revision is skipped; a request timeout stops priming
        (matching the previous behaviour) without aborting ``start()``.
        """
        revision = self._active_revision()
        if revision is None:
            logger.info(
                "No active TCX protocol revision available; skipping initial "
                "snapshot priming (cannot address parameters by wire id "
                "without a negotiated revision). Live notifications will "
                "populate the snapshot as they arrive."
            )
            return
        logger.info(
            "Priming TCX snapshot profile-aware (BikeParameter -> wire id) "
            "for %s revision 0x%02x",
            revision.generation.name,
            revision.revision,
        )
        for param in TCX_POLL_PARAMS:
            try:
                await self._conn.request_tcx_parameter(param)
            except UnmappedParameterError:
                logger.debug(
                    "No wire id for %s on %s revision 0x%02x; skipping prime",
                    param.name,
                    revision.generation.name,
                    revision.revision,
                )
                continue
            except TCXRequestTimeoutError:
                logger.warning(
                    "Timed out while priming TCX telemetry at parameter %s",
                    param.name,
                )
                break


async def run_telemetry_session(
    address: str,
    *,
    pin: str | None = None,
    duration: float = 0,
    output_format: str = "table",
    output_callback: Callable[[str], None] | None = None,
) -> TelemetrySnapshot:
    """
    Connect, print telemetry for a while, and return the final snapshot.

    Set duration=0 to run until Ctrl+C. output_format is "table" or "json".
    """
    printer = output_callback or print

    async with SpecializedConnection(address, pin=pin) as conn:
        monitor = TelemetryMonitor(conn)

        def _on_update(msg: ParsedMessage, snap: TelemetrySnapshot) -> None:
            if msg.field_name is None:
                return
            if output_format == "json":
                printer(json.dumps(snap.as_dict(), default=str))
            else:
                printer(
                    f"{msg.field_name:<28s} = {str(msg.converted_value):>10s} {msg.unit}"
                )

        monitor.on_update = _on_update
        await monitor.start()

        try:
            if duration > 0:
                await asyncio.sleep(duration)
            else:
                # Run forever until Ctrl+C
                while monitor.is_running:
                    await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await monitor.stop()

        return monitor.snapshot
