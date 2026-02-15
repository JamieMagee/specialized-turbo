"""
Telemetry monitoring for Specialized Turbo bikes.

Subscribes to BLE notifications, decodes them, and keeps a running
TelemetrySnapshot. Supports callbacks and async iteration.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import AsyncIterator, Callable

from bleak.backends.characteristic import BleakGATTCharacteristic

from .connection import SpecializedConnection
from .models import TelemetrySnapshot
from .protocol import parse_message, ParsedMessage

logger = logging.getLogger(__name__)


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

    def _notification_handler(
        self, characteristic: BleakGATTCharacteristic, data: bytearray
    ) -> None:
        """Called by bleak for each notification. Parses, updates snapshot, notifies consumers."""
        try:
            msg = parse_message(data)
        except Exception:
            logger.warning(
                "Failed to parse notification: %s", data.hex(), exc_info=True
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
