"""
Helpers for BLE coordinator integrations (e.g. Home Assistant).

These functions encapsulate device-specific protocol logic so that
integration coordinators can stay thin.  They work with an externally-
managed ``BleakClient`` (the integration controls connection lifecycle)
while the library handles parsing, polling, and identification.
"""

from __future__ import annotations

import asyncio
import logging

from bleak import BleakClient

from .framing import (
    is_framed_packet,
    is_nak_packet,
    parse_nak_packet,
)
from .key_provider import EncryptionKeyRequiredError
from .models import TelemetrySnapshot
from .parameters import BikeParameter
from .protocol import (
    TCU1_POLL_FIELDS,
    ParsedMessage,
    build_request,
    parse_message,
    parse_tcx_message,
)
from .session import ProtocolSession, TCXSession
from .transport import TCXNotificationTransport

logger = logging.getLogger(__name__)

#: TCX2+ parameter IDs to query through write/notification transactions.
TCX_POLL_PARAMS: tuple[BikeParameter, ...] = (
    BikeParameter.SYSTEM_STATE,
    BikeParameter.SYSTEM_RANGE_LONG,
    BikeParameter.SYSTEM_RANGE_SHORT,
    BikeParameter.SYSTEM_TEMPERATURE,
    BikeParameter.SYSTEM_CONSUMPTION,
    BikeParameter.SYSTEM_ALT,
    BikeParameter.SYSTEM_ALT_GAIN,
    BikeParameter.SYSTEM_GRADIENT,
    BikeParameter.BATTERY1_STATE_OF_CHARGE,
    BikeParameter.MOTOR_BIKE_SPEED,
    BikeParameter.MOTOR_BIKE_CADENCE,
    BikeParameter.MOTOR_POWER,
    BikeParameter.MOTOR_RIDER_INPUT_POWER,
    BikeParameter.MOTOR_TEMPERATURE,
)


def parse_notification(
    session: ProtocolSession,
    data: bytes,
) -> ParsedMessage:
    """Parse a BLE notification using the appropriate protocol format.

    Auto-detects whether *data* is a CRC-framed TCX packet or a bare
    TCU1 message, unpacks it through *session*, and returns a
    :class:`ParsedMessage`.

    Raises on parse failure (caller should catch and log).
    """
    if is_framed_packet(data):
        unpacked = session.unpack(data)
        return parse_tcx_message(unpacked)
    return parse_message(data)


async def poll_tcu1(
    client: BleakClient,
    char_request_write: str,
    char_request_read: str,
    snapshot: TelemetrySnapshot,
) -> bool:
    """Poll all TCU1 fields via request-read and update *snapshot*.

    Returns ``True`` if any field was updated.
    """
    updated = False
    for sender, channel in TCU1_POLL_FIELDS:
        try:
            await client.write_gatt_char(
                char_request_write, build_request(sender, channel)
            )
            await asyncio.sleep(0.1)
            response = await client.read_gatt_char(char_request_read)
            msg = parse_message(response)
            if msg.sender == sender and msg.channel == channel:
                snapshot.update_from_message(msg)
                updated = True
        except Exception:
            logger.debug(
                "Failed to poll TCU1 field (%02x, %02x)",
                sender,
                channel,
                exc_info=True,
            )
    return updated


async def poll_tcx(
    transport: TCXNotificationTransport,
    snapshot: TelemetrySnapshot,
) -> bool:
    """Poll TCX fields through write/notification transactions.

    Returns ``True`` if any field was updated.
    """
    updated = False
    for param in TCX_POLL_PARAMS:
        try:
            response = await transport.request_parameter(int(param))
            msg = parse_tcx_message(response)
            if msg.nak_reason is not None:
                logger.debug(
                    "TCX param %d rejected with reason 0x%02x",
                    int(param),
                    msg.nak_reason,
                )
                continue
            snapshot.update_from_message(msg)
            updated = True
        except Exception:
            logger.debug("Failed to poll TCX param %d", int(param), exc_info=True)
    return updated


async def identify_tcx(
    transport: TCXNotificationTransport,
    *,
    bike_key: bytes | None = None,
    encryption_required: bool = False,
) -> TCXSession:
    """Run the TCX identification handshake and return a session.

    The first request is clear and returns the 16-byte session IV. When
    *bike_key* is provided, subsequent identification requests are encrypted.
    """
    steps = [
        BikeParameter.SYSTEM_GET_NEW_VI,
        BikeParameter.SYSTEM_HMI_PROTOCOL_VERSION,
        BikeParameter.SYSTEM_STATE,
        BikeParameter.BATTERY1_FIRMWARE,
        BikeParameter.SYSTEM_HMI_HW_VERSION,
        BikeParameter.SYSTEM_MOTOR_TYPE,
        BikeParameter.SYSTEM_EBIKE_SERIAL_NUMBER,
    ]

    try:
        for index, param in enumerate(steps):
            inner = await transport.request_parameter(int(param))

            if is_nak_packet(inner):
                echoed, reason = parse_nak_packet(inner)
                logger.warning(
                    "Identification step %d (%s) rejected by bike: "
                    "echoed_param=%d reason=0x%02x",
                    int(param),
                    param.name,
                    echoed,
                    reason,
                )
                if encryption_required:
                    raise EncryptionKeyRequiredError(
                        f"Encrypted identification step {int(param)} was rejected"
                    )
                continue

            if index == 0:
                iv = inner[2:18]
                if len(iv) != 16:
                    if encryption_required:
                        raise EncryptionKeyRequiredError(
                            f"Expected a 16-byte session IV, got {len(iv)}"
                        )
                    logger.warning(
                        "Invalid TCX session IV length %d; using unencrypted session",
                        len(iv),
                    )
                    continue
                if bike_key is not None:
                    transport.session = TCXSession(key=bike_key, iv=iv)
    except EncryptionKeyRequiredError:
        raise
    except Exception as exc:
        if encryption_required:
            raise EncryptionKeyRequiredError(
                "Encrypted TCX identification failed"
            ) from exc
        logger.warning(
            "TCX identification handshake failed, using unencrypted session",
            exc_info=True,
        )
        return TCXSession()

    session = transport.session
    if encryption_required and not session.encrypted:
        raise EncryptionKeyRequiredError(
            "Bike requires encryption but no encrypted session was established"
        )
    return session
