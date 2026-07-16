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
from .parameters import decode_parameter_id, encode_parameter_id
from .protocol import (
    BLEProfile,
    BLEServiceID,
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
    """Raised when a TCX request has no matching notification response.

    ``param_id`` is the 16-bit **wire command id** that was written and never
    answered (a NAK would have echoed it).  It is not necessarily a
    :class:`~specialized_turbo.parameters.BikeParameter` value -- on a real
    bike the two spaces differ (see :mod:`specialized_turbo.wire_profiles`).
    """

    def __init__(self, param_id: int, timeout: float) -> None:
        super().__init__(
            f"Timed out after {timeout:g}s waiting for TCX parameter {param_id}"
        )
        self.param_id = param_id
        self.timeout = timeout


class TCXTransportDisconnectedError(ConnectionError):
    """Raised when the BLE link closes during a TCX transaction."""


@dataclass(slots=True)
class _PendingRequest:
    wire_id: int
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
        self._disconnected = False

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

    def mark_disconnected(self) -> None:
        """Fail any in-flight request after the BLE link closes."""
        self._disconnected = True
        pending = self._pending
        if pending is not None and not pending.future.done():
            pending.future.set_exception(
                TCXTransportDisconnectedError(
                    "Bike disconnected during TCX transaction"
                )
            )

    async def subscribe(self, service_id: BLEServiceID) -> None:
        """Enable notifications for one TCX service."""
        self._raise_if_disconnected()
        if service_id in self._subscribed:
            return

        characteristic = get_service_characteristics(BLEProfile.TCX, service_id).notify

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

    async def request_wire_parameter(
        self,
        wire_id: int,
        *,
        body: bytes | bytearray = b"",
        timeout: float | None = None,
    ) -> bytes:
        """Read by wire command id, correlating the response by that wire id.

        Writes ``[wire_id_be] + body`` to service 1 and awaits the matching
        notification.  Correlation is on the 16-bit **wire id** (the clear
        2-byte header of the response, which a NAK echoes back), not on any
        :class:`~specialized_turbo.parameters.BikeParameter` value -- the
        caller is responsible for mapping app-level parameters to wire ids
        via :mod:`specialized_turbo.wire_profiles`.

        *body* carries any extra request bytes (e.g. the single required zero
        byte of the ``0x0A00`` ``GET_NEW_VI`` identification request).  The
        returned payload is unpacked through the active session (decrypted
        and CRC-stripped for encrypted reads, passed through for clear
        control/NAK frames).
        """
        await self.subscribe_for_identification()
        payload = encode_parameter_id(wire_id) + bytes(body)
        return await self._request(
            wire_id,
            self._session.pack(payload),
            BLEServiceID.REQUEST,
            timeout=timeout,
        )

    async def request_parameter(
        self,
        param_id: int,
        *,
        timeout: float | None = None,
    ) -> bytes:
        """Read a parameter, treating *param_id* directly as the wire id.

        .. deprecated::
           Legacy shim retained for callers that historically pass
           :class:`~specialized_turbo.parameters.BikeParameter` values that
           coincide with wire ids.  New code should resolve the wire id
           explicitly (via :mod:`specialized_turbo.wire_profiles`) and call
           :meth:`request_wire_parameter`.
        """
        return await self.request_wire_parameter(param_id, timeout=timeout)

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
        self._raise_if_disconnected()
        characteristic = get_service_characteristics(BLEProfile.TCX, service_id).write
        packet = bytes(data)
        self._emit_trace("tx", service_id, characteristic, packet)
        await self._client.write_gatt_char(
            characteristic,
            packet,
            response=False,
        )

    async def _request(
        self,
        wire_id: int,
        frame: bytes,
        service_id: BLEServiceID,
        *,
        timeout: float | None,
    ) -> bytes:
        request_timeout = self._request_timeout if timeout is None else timeout
        self._raise_if_disconnected()

        async with self._request_lock:
            self._raise_if_disconnected()
            future = asyncio.get_running_loop().create_future()
            self._pending = _PendingRequest(wire_id, service_id, future)
            try:
                await self.write_frame(service_id, frame)
                try:
                    response = await asyncio.wait_for(future, request_timeout)
                except TimeoutError as exc:
                    raise TCXRequestTimeoutError(wire_id, request_timeout) from exc
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
                response_wire_id = self._response_wire_id(packet)
            except ValueError:
                logger.debug(
                    "Ignoring uncorrelated TCX notification on service %d: %s",
                    int(service_id),
                    packet.hex(),
                )
            else:
                if response_wire_id == pending.wire_id:
                    pending.future.set_result(packet)

        for listener in tuple(self._listeners):
            try:
                listener(sender, bytearray(packet))
            except Exception:
                logger.warning("TCX notification listener raised", exc_info=True)

    def _response_wire_id(self, packet: bytes) -> int:
        """Wire command id a response correlates to (a NAK echoes it)."""
        payload = self._session.unpack(packet)
        if is_nak_packet(payload):
            wire_id, _reason = parse_nak_packet(payload)
            return wire_id
        return decode_parameter_id(payload)

    def _raise_if_disconnected(self) -> None:
        if self._disconnected:
            raise TCXTransportDisconnectedError(
                "Bike disconnected during TCX transaction"
            )

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
