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

from .encryption import derive_key
from .framing import (
    is_framed_packet,
    is_nak_packet,
    parse_nak_packet,
    unpack_tcx,
)
from .models import TelemetrySnapshot
from .parameters import BikeParameter
from .protocol import (
    TCU1_POLL_FIELDS,
    build_request,
    build_tcx_request,
    parse_message,
    parse_tcx_message,
    ParsedMessage,
)
from .session import ProtocolSession, TCXSession

logger = logging.getLogger(__name__)

#: TCX2+ parameter IDs to poll via request-read.
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
        except Exception:  # noqa: BLE001
            logger.debug(
                "Failed to poll TCU1 field (%02x, %02x)",
                sender,
                channel,
                exc_info=True,
            )
    return updated


async def poll_tcx(
    client: BleakClient,
    session: ProtocolSession,
    char_request_write: str,
    char_request_read: str,
    snapshot: TelemetrySnapshot,
) -> bool:
    """Poll TCX system fields via request-read and update *snapshot*.

    Returns ``True`` if any field was updated.
    """
    updated = False
    for param in TCX_POLL_PARAMS:
        try:
            request = build_tcx_request(int(param))
            await client.write_gatt_char(char_request_write, request)
            await asyncio.sleep(0.1)
            response = await client.read_gatt_char(char_request_read)
            unpacked = session.unpack(response)
            msg = parse_tcx_message(unpacked)
            snapshot.update_from_message(msg)
            updated = True
        except Exception:  # noqa: BLE001
            logger.debug("Failed to poll TCX param %d", int(param), exc_info=True)
    return updated


async def identify_tcx(
    client: BleakClient,
    char_request_write: str,
    char_request_read: str,
) -> TCXSession:
    """Run the TCX identification handshake and return a session.

    Executes the full 7-step identification sequence.  Step 4 may
    return encryption key material.  Returns an encrypted
    :class:`TCXSession` if a key is found, or an unencrypted one
    otherwise.

    If the handshake fails, returns an unencrypted session.
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

    key_response: bytes | None = None

    try:
        for param in steps:
            request = build_tcx_request(int(param))
            await client.write_gatt_char(char_request_write, request)
            await asyncio.sleep(0.15)
            response = await client.read_gatt_char(char_request_read)
            inner = bytes(response)
            if is_framed_packet(inner):
                try:
                    inner = unpack_tcx(inner)
                except ValueError:
                    pass

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
                continue

            if param == BikeParameter.BATTERY1_FIRMWARE:
                key_response = inner
    except Exception:  # noqa: BLE001
        logger.warning(
            "TCX identification handshake failed, using unencrypted session",
            exc_info=True,
        )
        return TCXSession()

    if key_response is None or len(key_response) < 4:
        return TCXSession()

    # key_response is the inner payload with CRC and any NAK already
    # filtered above.  Skip the 2-byte param ID to reach key material.
    key_data = key_response[2:].rstrip(b"\x00")

    if len(key_data) == 0:
        logger.debug(
            "Encryption key response was empty — bike may not require encryption"
        )
        return TCXSession()

    # A valid base64 encryption key is 64 chars (~48 decoded bytes).
    # Short responses (e.g. a single firmware-version byte) are not keys.
    if len(key_data) < 20:
        logger.debug(
            "Key response too short for encryption (%d bytes) "
            "— bike does not require encryption",
            len(key_data),
        )
        return TCXSession()

    try:
        aes_key = derive_key(key_data.decode("ascii"))
        logger.info("TCX encryption key derived, using encrypted session")
        return TCXSession(key=aes_key, iv=b"\x00" * 16)
    except Exception:  # noqa: BLE001
        logger.warning(
            "Failed to derive encryption key, using unencrypted session",
            exc_info=True,
        )
        return TCXSession()
