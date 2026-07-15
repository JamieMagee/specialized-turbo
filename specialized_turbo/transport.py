"""TCX request/response transport over BLE writes and notifications."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic

from .framing import is_nak_packet, parse_nak_packet
from .parameters import decode_parameter_id
from .protocol import (
    BLEProfile,
    BLEServiceID,
    build_tcx_request,
    build_tcx_write,
    get_service_characteristics,
)
from .session import TCXSession

logger = logging.getLogger(__name__)

NotificationCallback = Callable[
    [BleakGATTCharacteristic, bytearray],
    None,
]
TraceDirection = Literal["tx", "rx"]


@dataclass(frozen=True, slots=True)
class BLETraceEvent:
    """One raw BLE packet sent or received by the TCX transport."""

    timestamp: float
    direction: TraceDirection
    service_id: BLEServiceID
    characteristic: str
    data: bytes


TraceCallback = Callable[[BLETraceEvent], None]


class TCXRequestTimeoutError(TimeoutError):
    """Raised when a TCX request has no matching notification response."""

    def __init__(self, param_id: int, timeout: float) -> None:
        super().__init__(
            f"Timed out after {timeout:g}s waiting for TCX parameter {param_id}"
        )
        self.param_id = param_id
        self.timeout = timeout


@dataclass(slots=True)
class _PendingRequest:
    param_id: int
    service_id: BLEServiceID
    future: asyncio.Future[bytes]


class TCXNotificationTransport:
    """Send TCX frames and correlate responses delivered as notifications."""

    def __init__(
        self,
        client: BleakClient,
        *,
        session: TCXSession | None = None,
        request_timeout: float = 7.0,
        trace_callback: TraceCallback | None = None,
    ) -> None:
        self._client = client
        self._session = session or TCXSession()
        self._request_timeout = request_timeout
        self._trace_callback = trace_callback
        self._listeners: list[NotificationCallback] = []
        self._subscribed: set[BLEServiceID] = set()
        self._pending: _PendingRequest | None = None
        self._request_lock = asyncio.Lock()

    @property
    def session(self) -> TCXSession:
        """Active framing/encryption session."""
        return self._session

    @session.setter
    def session(self, session: TCXSession) -> None:
        self._session = session

    def add_listener(self, callback: NotificationCallback) -> None:
        """Forward incoming notifications to *callback*."""
        if callback not in self._listeners:
            self._listeners.append(callback)

    def remove_listener(self, callback: NotificationCallback) -> None:
        """Stop forwarding incoming notifications to *callback*."""
        if callback in self._listeners:
            self._listeners.remove(callback)

    async def subscribe(self, service_id: BLEServiceID) -> None:
        """Enable notifications for one TCX service."""
        if service_id in self._subscribed:
            return

        characteristic = get_service_characteristics(
            BLEProfile.TCX, service_id
        ).notify

        def callback(
            sender: BleakGATTCharacteristic,
            data: bytearray,
        ) -> None:
            self._handle_notification(service_id, sender, data)

        await self._client.start_notify(characteristic, callback)
        self._subscribed.add(service_id)
        logger.debug(
            "Subscribed to TCX service %d notifications (%s)",
            int(service_id),
            characteristic,
        )

    async def subscribe_for_identification(self) -> None:
        """Subscribe to the service used by identification and reads."""
        await self.subscribe(BLEServiceID.REQUEST)

    async def subscribe_for_realtime(self) -> None:
        """Subscribe to the remaining services before enabling live data."""
        await self.subscribe(BLEServiceID.DATA)
        await self.subscribe(BLEServiceID.COMMAND)

    async def unsubscribe_all(self) -> None:
        """Disable every notification subscription owned by this transport."""
        for service_id in tuple(self._subscribed):
            characteristic = get_service_characteristics(
                BLEProfile.TCX, service_id
            ).notify
            await self._client.stop_notify(characteristic)
            self._subscribed.remove(service_id)

    async def request_parameter(
        self,
        param_id: int,
        *,
        timeout: float | None = None,
    ) -> bytes:
        """Read a parameter by writing a request and awaiting its notification."""
        await self.subscribe_for_identification()
        payload = build_tcx_request(param_id)
        return await self._request(
            param_id,
            self._session.pack(payload),
            BLEServiceID.REQUEST,
            timeout=timeout,
        )

    async def write_parameter(
        self,
        param_id: int,
        data: bytes | bytearray,
    ) -> None:
        """Write a parameter on service 3 without waiting for a GATT response."""
        payload = build_tcx_write(param_id, data)
        await self.write_frame(
            BLEServiceID.DATA,
            self._session.pack(payload),
        )

    async def set_realtime_enabled(self, enabled: bool) -> None:
        """Enable or disable the bike's real-time telemetry stream."""
        from .parameters import BikeParameter

        await self.subscribe_for_realtime()
        await self.write_parameter(
            int(BikeParameter.SYSTEM_REAL_TIME_DATA_ENB),
            bytes([enabled]),
        )

    async def write_frame(
        self,
        service_id: BLEServiceID,
        data: bytes | bytearray,
    ) -> None:
        """Write an already-framed packet without response."""
        characteristic = get_service_characteristics(
            BLEProfile.TCX, service_id
        ).write
        packet = bytes(data)
        self._emit_trace("tx", service_id, characteristic, packet)
        await self._client.write_gatt_char(
            characteristic,
            packet,
            response=False,
        )

    async def _request(
        self,
        param_id: int,
        frame: bytes,
        service_id: BLEServiceID,
        *,
        timeout: float | None,
    ) -> bytes:
        request_timeout = self._request_timeout if timeout is None else timeout

        async with self._request_lock:
            future = asyncio.get_running_loop().create_future()
            self._pending = _PendingRequest(param_id, service_id, future)
            try:
                await self.write_frame(service_id, frame)
                try:
                    response = await asyncio.wait_for(future, request_timeout)
                except TimeoutError as exc:
                    raise TCXRequestTimeoutError(param_id, request_timeout) from exc
                return self._session.unpack(response)
            finally:
                if self._pending is not None and self._pending.future is future:
                    self._pending = None

    def _handle_notification(
        self,
        service_id: BLEServiceID,
        sender: BleakGATTCharacteristic,
        data: bytearray,
    ) -> None:
        packet = bytes(data)
        characteristic = sender.uuid
        self._emit_trace("rx", service_id, characteristic, packet)

        pending = self._pending
        if (
            pending is not None
            and pending.service_id == service_id
            and not pending.future.done()
        ):
            try:
                response_param = self._response_param_id(packet)
            except ValueError:
                logger.debug(
                    "Ignoring uncorrelated TCX notification on service %d: %s",
                    int(service_id),
                    packet.hex(),
                )
            else:
                if response_param == pending.param_id:
                    pending.future.set_result(packet)

        for listener in tuple(self._listeners):
            try:
                listener(sender, bytearray(packet))
            except Exception:
                logger.warning("TCX notification listener raised", exc_info=True)

    def _response_param_id(self, packet: bytes) -> int:
        payload = self._session.unpack(packet)
        if is_nak_packet(payload):
            param_id, _reason = parse_nak_packet(payload)
            return param_id
        return decode_parameter_id(payload)

    def _emit_trace(
        self,
        direction: TraceDirection,
        service_id: BLEServiceID,
        characteristic: str,
        data: bytes,
    ) -> None:
        if self._trace_callback is None:
            return
        try:
            self._trace_callback(
                BLETraceEvent(
                    timestamp=time.monotonic(),
                    direction=direction,
                    service_id=service_id,
                    characteristic=characteristic,
                    data=data,
                )
            )
        except Exception:
            logger.warning("BLE trace callback raised", exc_info=True)
