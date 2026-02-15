"""
Real-time telemetry monitoring for Specialized Turbo bikes.

Subscribes to BLE notifications, decodes each message, and maintains
a live ``TelemetrySnapshot``. Supports callbacks and async iteration.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import AsyncIterator, Callable

from .connection import SpecializedConnection
from .models import TelemetrySnapshot
from .protocol import parse_message, ParsedMessage

logger = logging.getLogger(__name__)


class TelemetryMonitor:
    """
    High-level telemetry stream from a Specialized Turbo bike.

    Usage::

        async with SpecializedConnection(address, pin=pin) as conn:
            monitor = TelemetryMonitor(conn)
            await monitor.start()

            # Option A: poll the snapshot
            print(monitor.snapshot.motor.speed_kmh)

            # Option B: register a callback
            monitor.on_update = lambda msg, snap: print(snap.as_dict())

            # Option C: async iterate
            async for msg in monitor.stream():
                print(f"{msg.field_name} = {msg.converted_value} {msg.unit}")

            await monitor.stop()

    Parameters
    ----------
    connection : SpecializedConnection
        An established BLE connection to the bike.
    """

    def __init__(self, connection: SpecializedConnection) -> None:
        self._conn = connection
        self._snapshot = TelemetrySnapshot()
        self._running = False
        self._queue: asyncio.Queue[ParsedMessage] = asyncio.Queue()
        self.on_update: Callable[[ParsedMessage, TelemetrySnapshot], None] | None = None
        """Optional callback invoked after each notification is processed."""

    @property
    def snapshot(self) -> TelemetrySnapshot:
        """Current aggregated telemetry state (updated in-place)."""
        return self._snapshot

    @property
    def is_running(self) -> bool:
        return self._running

    async def start(self) -> None:
        """Subscribe to bike notifications and begin decoding."""
        if self._running:
            return
        self._running = True
        await self._conn.subscribe_notifications(self._notification_handler)
        logger.info("TelemetryMonitor started")

    async def stop(self) -> None:
        """Unsubscribe from notifications."""
        if not self._running:
            return
        self._running = False
        await self._conn.unsubscribe_notifications()
        # Unblock any waiting stream consumers
        await self._queue.put(None)  # type: ignore[arg-type]
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

    def _notification_handler(self, sender_handle: int, data: bytearray) -> None:
        """
        Internal callback invoked by bleak for each BLE notification.

        Parses the raw bytes, updates the snapshot, fires ``on_update``,
        and enqueues the message for ``stream()`` consumers.
        """
        try:
            msg = parse_message(data)
        except Exception:
            logger.warning("Failed to parse notification: %s", data.hex(), exc_info=True)
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

        try:
            self._queue.put_nowait(msg)
        except asyncio.QueueFull:
            pass  # drop oldest if consumer is too slow


async def run_telemetry_session(
    address: str,
    *,
    pin: int | None = None,
    duration: float = 0,
    output_format: str = "table",
    output_callback: Callable[[str], None] | None = None,
) -> TelemetrySnapshot:
    """
    Convenience function: connect, stream telemetry, and return snapshot.

    Parameters
    ----------
    address : str
        BLE MAC address of the bike.
    pin : int | None
        Pairing PIN.
    duration : float
        How long to collect data (seconds). 0 = run until interrupted.
    output_format : str
        ``"table"`` for human-readable lines, ``"json"`` for JSON per update.
    output_callback :
        Called with each formatted output line. Defaults to ``print``.

    Returns
    -------
    TelemetrySnapshot
        Final aggregated state.
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
