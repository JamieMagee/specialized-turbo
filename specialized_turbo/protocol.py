"""
Specialized Turbo BLE protocol.

UUIDs, message format, enums, and parsing. Ported from the
Sepp62/LevoEsp32Ble C++ project (MIT).

Supports two protocol generations:
- TCX ("TURBOHMI2017"): Vado/Levo/Creo 2019+, Nordic manufacturer ID
- TCU1 ("GIGATRONIK"): Levo 2018, Simplo manufacturer ID

Both generations share the same message format and field definitions;
only the BLE UUIDs and advertisement data differ.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Protocol generation
# ---------------------------------------------------------------------------


class BLEProfile(StrEnum):
    """BLE protocol generation for Specialized Turbo bikes."""

    TCU1 = "tcu1"  # 2018 Levo (Gigatronik TCU, Simplo mfr ID)
    TCX = "tcx"  # 2019+ Vado/Levo/Creo (TURBOHMI2017, Nordic mfr ID)


class ProtocolEncryptionMethod(IntEnum):
    """Application-layer encryption declared by a bike advertisement."""

    NONE = 0
    AES_CTR = 1


class BLEServiceID(IntEnum):
    """Logical Specialized GATT service."""

    REQUEST = 1
    COMMAND = 2
    DATA = 3


@dataclass(frozen=True, slots=True)
class BLEServiceCharacteristics:
    """UUIDs for one Specialized service's notify/write pair."""

    service: str
    notify: str
    write: str


# ---------------------------------------------------------------------------
# UUID definitions
# ---------------------------------------------------------------------------

# TCX base UUID: 000000xx-3731-3032-494d-484f42525554
# Last 12 bytes = "7102IMHOBRUT" = reverse of "TURBOHMI2017"
TCX_UUID_BASE = "0000{:04x}-3731-3032-494d-484f42525554"

# TCU1 base UUID: 000000xx-0000-4b49-4e4f-525441474947
# Last 10 bytes = "KINORTAGIG" = reverse of "GIGATRONIK"
TCU1_UUID_BASE = "0000{:04x}-0000-4b49-4e4f-525441474947"

# Backward-compatible alias (TCX)
UUID_BASE = TCX_UUID_BASE

_UUID_BASES: dict[BLEProfile, str] = {
    BLEProfile.TCU1: TCU1_UUID_BASE,
    BLEProfile.TCX: TCX_UUID_BASE,
}


def _uuid(short: int) -> str:
    """Expand a short UUID into the full 128-bit TCX UUID."""
    return TCX_UUID_BASE.format(short)


def _uuid_tcu1(short: int) -> str:
    """Expand a short UUID into the full 128-bit TCU1 UUID."""
    return TCU1_UUID_BASE.format(short)


def get_uuid(generation: BLEProfile, short: int) -> str:
    """Expand a short UUID for the given protocol generation."""
    return _UUID_BASES[generation].format(short)


# ------ TCX UUIDs (default, backward-compatible) ------

# Service UUIDs
SERVICE_DATA_NOTIFY = _uuid(0x0003)  # Notification data service
SERVICE_DATA_REQUEST = _uuid(0x0001)  # Request-read service
SERVICE_DATA_WRITE = _uuid(0x0002)  # Write command service

# Characteristic UUIDs
CHAR_NOTIFY = _uuid(0x0013)  # READ, NOTIFY — bike pushes telemetry here
CHAR_REQUEST_WRITE = _uuid(0x0021)  # WRITE_NO_RESP — send requests here
CHAR_REQUEST_READ = _uuid(0x0011)  # READ, NOTIFY — request responses arrive here
CHAR_WRITE = _uuid(0x0012)  # READ, NOTIFY — command responses arrive here
CHAR_WRITE_NO_RESP_S2 = _uuid(
    0x0022
)  # WRITE_NO_RESP — command / ride-log writes (service 2)
CHAR_WRITE_NO_RESP_S3 = _uuid(
    0x0023
)  # WRITE_NO_RESP — parameter writes / stream control (service 3)

# Canonical role names. Keep the older names above for compatibility.
CHAR_REQUEST_NOTIFY = CHAR_REQUEST_READ
CHAR_COMMAND_NOTIFY = CHAR_WRITE
CHAR_COMMAND_WRITE = CHAR_WRITE_NO_RESP_S2
CHAR_DATA_NOTIFY = CHAR_NOTIFY
CHAR_DATA_WRITE = CHAR_WRITE_NO_RESP_S3

# ------ TCU1 UUIDs ------

SERVICE_DATA_NOTIFY_TCU1 = _uuid_tcu1(0x0003)
SERVICE_DATA_REQUEST_TCU1 = _uuid_tcu1(0x0001)
SERVICE_DATA_WRITE_TCU1 = _uuid_tcu1(0x0002)

CHAR_NOTIFY_TCU1 = _uuid_tcu1(0x0013)
CHAR_REQUEST_WRITE_TCU1 = _uuid_tcu1(0x0021)
CHAR_REQUEST_READ_TCU1 = _uuid_tcu1(0x0011)
CHAR_WRITE_TCU1 = _uuid_tcu1(0x0012)
CHAR_WRITE_NO_RESP_S2_TCU1 = _uuid_tcu1(0x0022)
CHAR_WRITE_NO_RESP_S3_TCU1 = _uuid_tcu1(0x0023)

# ------ Generation → UUID lookup ------

_CHAR_NOTIFY_MAP: dict[BLEProfile, str] = {
    BLEProfile.TCU1: CHAR_NOTIFY_TCU1,
    BLEProfile.TCX: CHAR_NOTIFY,
}

_CHAR_REQUEST_READ_MAP: dict[BLEProfile, str] = {
    BLEProfile.TCU1: CHAR_REQUEST_READ_TCU1,
    BLEProfile.TCX: CHAR_REQUEST_READ,
}

_CHAR_REQUEST_WRITE_MAP: dict[BLEProfile, str] = {
    BLEProfile.TCU1: CHAR_REQUEST_WRITE_TCU1,
    BLEProfile.TCX: CHAR_REQUEST_WRITE,
}

_CHAR_WRITE_MAP: dict[BLEProfile, str] = {
    BLEProfile.TCU1: CHAR_WRITE_TCU1,
    BLEProfile.TCX: CHAR_WRITE,
}


def get_char_notify(generation: BLEProfile) -> str:
    """Return the CHAR_NOTIFY UUID for the given protocol generation."""
    return _CHAR_NOTIFY_MAP[generation]


def get_char_request_read(generation: BLEProfile) -> str:
    """Return the CHAR_REQUEST_READ UUID for the given protocol generation."""
    return _CHAR_REQUEST_READ_MAP[generation]


def get_char_request_write(generation: BLEProfile) -> str:
    """Return the CHAR_REQUEST_WRITE UUID for the given protocol generation."""
    return _CHAR_REQUEST_WRITE_MAP[generation]


def get_char_write(generation: BLEProfile) -> str:
    """Return the CHAR_WRITE UUID for the given protocol generation."""
    return _CHAR_WRITE_MAP[generation]


def get_service_characteristics(
    generation: BLEProfile,
    service_id: BLEServiceID,
) -> BLEServiceCharacteristics:
    """Return the notify/write UUID pair for a Specialized GATT service."""
    service = int(service_id)
    return BLEServiceCharacteristics(
        service=get_uuid(generation, service),
        notify=get_uuid(generation, 0x0010 | service),
        write=get_uuid(generation, 0x0020 | service),
    )


# ---------------------------------------------------------------------------
# BLE company IDs
# ---------------------------------------------------------------------------

# Nordic Semiconductor (TCX bikes)
NORDIC_COMPANY_ID = 0x0059

# Apple Inc. (some TCX bikes advertise TURBOHMI in an iBeacon frame)
APPLE_COMPANY_ID = 0x004C

# Simplo Technology Co., LTD (TCU1 bikes)
SIMPLO_COMPANY_ID = 0x020D

# Magic advertising string embedded in TCX manufacturer data
ADVERTISING_MAGIC = b"TURBOHMI"

# Standard Bluetooth Cycling Speed and Cadence service (TCU1 bikes may advertise)
CYCLING_SPEED_CADENCE_SERVICE = "00001816-0000-1000-8000-00805f9b34fb"
_SPECIALIZED_NAME_PATTERN = re.compile(
    r"^(?:SPECIALIZED(?:\s?[A-Z\d]+)?|(?:WSBC)?\d{3,9}[A-Z])"
    r"(?:\s-\sFind My)?$",
    re.IGNORECASE,
)
_TCX_SERVICE_UUIDS = {
    SERVICE_DATA_REQUEST.lower(),
    SERVICE_DATA_WRITE.lower(),
    SERVICE_DATA_NOTIFY.lower(),
}


@dataclass(frozen=True, slots=True)
class BikeAdvertisement:
    """Protocol metadata decoded from BLE manufacturer data."""

    generation: BLEProfile
    encryption: ProtocolEncryptionMethod = ProtocolEncryptionMethod.NONE
    hmi_serial: str | None = None
    hmi_hardware: str | None = None
    bike_type: int | None = None
    system_state: int | None = None
    reserved: int | None = None


# ---------------------------------------------------------------------------
# Protocol enums
# ---------------------------------------------------------------------------


class Sender(IntEnum):
    """Which subsystem sent the message."""

    BATTERY = 0x00
    MOTOR = 0x01  # Motor / rider data
    BIKE_SETTINGS = 0x02
    UNKNOWN_03 = 0x03
    BATTERY_2 = 0x04  # Secondary / range-extender battery (same channels as BATTERY)


class BatteryChannel(IntEnum):
    """Channels for Sender.BATTERY (0x00) and Sender.BATTERY_2 (0x04)."""

    SIZE_WH = 0x00
    REMAIN_WH = 0x01
    HEALTH = 0x02
    TEMP = 0x03
    CHARGE_CYCLES = 0x04
    VOLTAGE = 0x05
    CURRENT = 0x06
    CHARGE_PERCENT = 0x0C


class MotorChannel(IntEnum):
    """Channels for Sender.MOTOR (0x01)."""

    RIDER_POWER = 0x00
    CADENCE = 0x01
    SPEED = 0x02
    ODOMETER = 0x04
    ASSIST_LEVEL = 0x05
    MOTOR_TEMP = 0x07
    MOTOR_POWER = 0x0C
    PEAK_ASSIST = 0x10
    SHUTTLE = 0x15


class BikeSettingsChannel(IntEnum):
    """Channels for Sender.BIKE_SETTINGS (0x02)."""

    WHEEL_CIRCUMFERENCE = 0x00
    ASSIST_LEV1 = 0x03
    ASSIST_LEV2 = 0x04
    ASSIST_LEV3 = 0x05
    FAKE_CHANNEL = 0x06
    ACCELERATION = 0x07


class AssistLevel(IntEnum):
    """Write or read via MotorChannel.ASSIST_LEVEL."""

    OFF = 0
    ECO = 1
    TRAIL = 2
    TURBO = 3


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------


def _int_from_bytes(data: bytes | bytearray, offset: int, size: int) -> int:
    """Extract a little-endian unsigned int of *size* bytes at *offset*."""
    return int.from_bytes(
        data[offset : offset + size], byteorder="little", signed=False
    )


# Lookup: (sender, channel) → (data_size_bytes, human_name, unit, conversion_fn)
# conversion_fn takes the raw integer and returns a float/int in human units.

_FIELD_DEFS: dict[tuple[int, int], FieldDefinition] = {}


def _identity(v: int) -> int:
    """Identity conversion (no-op)."""
    return v


@dataclass(frozen=True, slots=True)
class FieldDefinition:
    """Metadata for a single protocol field."""

    sender: int
    channel: int
    name: str
    unit: str
    data_size: int  # bytes of payload (after sender+channel)
    convert: Callable[[int], float | int]
    writable: bool = False
    encode: Callable[[float | int], int] | None = None

    @property
    def key(self) -> tuple[int, int]:
        return (self.sender, self.channel)


def _reg(
    sender: int,
    channel: int,
    name: str,
    unit: str,
    size: int,
    convert: Callable[[int], float | int] | None = None,
    *,
    writable: bool = False,
    encode: Callable[[float | int], int] | None = None,
) -> None:
    if convert is None:
        convert = _identity
    fd = FieldDefinition(
        sender=sender,
        channel=channel,
        name=name,
        unit=unit,
        data_size=size,
        convert=convert,
        writable=writable,
        encode=encode,
    )
    _FIELD_DEFS[fd.key] = fd


# --- Battery fields (sender 0x00 / 0x04) ---
_reg(0x00, 0x00, "battery_capacity_wh", "Wh", 2, lambda v: round(v * 1.1111))
_reg(0x00, 0x01, "battery_remaining_wh", "Wh", 2, lambda v: round(v * 1.1111))
_reg(0x00, 0x02, "battery_health", "%", 1)
_reg(0x00, 0x03, "battery_temp", "°C", 1)
_reg(0x00, 0x04, "battery_charge_cycles", "cycles", 2)
_reg(0x00, 0x05, "battery_voltage", "V", 1, lambda v: v / 5.0 + 20.0)
_reg(0x00, 0x06, "battery_current", "A", 1, lambda v: v / 5.0)
_reg(0x00, 0x0C, "battery_charge_percent", "%", 1)

# --- Motor / rider fields (sender 0x01) ---
_reg(0x01, 0x00, "rider_power", "W", 2)
_reg(0x01, 0x01, "cadence", "RPM", 2, lambda v: v / 10.0)
_reg(0x01, 0x02, "speed", "km/h", 2, lambda v: v / 10.0)
_reg(0x01, 0x04, "odometer", "km", 4, lambda v: v / 1000.0)
_reg(
    0x01,
    0x05,
    "assist_level",
    "",
    2,
    lambda v: AssistLevel(v) if v in AssistLevel._value2member_map_ else v,
    writable=True,
    encode=lambda v: int(v),
)
_reg(0x01, 0x07, "motor_temp", "°C", 1)
_reg(0x01, 0x0C, "motor_power", "W", 2)
_reg(0x01, 0x10, "peak_assist", "", 3)  # 3 bytes: ECO%, TRAIL%, TURBO%
_reg(0x01, 0x15, "shuttle", "", 1, writable=True, encode=lambda v: int(v))

# --- Bike settings fields (sender 0x02) ---
_reg(0x02, 0x00, "wheel_circumference", "mm", 2, writable=True, encode=lambda v: int(v))
_reg(0x02, 0x03, "assist_lev1_pct", "%", 1, writable=True, encode=lambda v: int(v))
_reg(0x02, 0x04, "assist_lev2_pct", "%", 1, writable=True, encode=lambda v: int(v))
_reg(0x02, 0x05, "assist_lev3_pct", "%", 1, writable=True, encode=lambda v: int(v))
_reg(0x02, 0x06, "fake_channel", "", 1)
_reg(
    0x02,
    0x07,
    "acceleration",
    "%",
    2,
    lambda v: (v - 3000) / 60.0,
    writable=True,
    encode=lambda v: int(v * 60 + 3000),
)

# Duplicate battery fields for secondary battery (sender 0x04) — same channels
for _ch in list(BatteryChannel):
    _orig = _FIELD_DEFS.get((0x00, _ch))
    if _orig:
        _reg(
            0x04,
            _ch,
            _orig.name.replace("battery_", "battery2_"),
            _orig.unit,
            _orig.data_size,
            _orig.convert,
        )


def get_field_def(sender: int, channel: int) -> FieldDefinition | None:
    """Return the field definition for a (sender, channel) pair, or None."""
    return _FIELD_DEFS.get((sender, channel))


def all_field_defs() -> dict[tuple[int, int], FieldDefinition]:
    """Return a copy of all registered field definitions."""
    return dict(_FIELD_DEFS)


# ---------------------------------------------------------------------------
# Message parsing
# ---------------------------------------------------------------------------


class ParsedMessage(NamedTuple):
    """A decoded BLE notification or read-response."""

    sender: int
    channel: int
    raw_value: int
    converted_value: float | int | AssistLevel | None
    field_name: str | None  # None if field is unknown or response was a NAK
    unit: str
    nak_reason: int | None = None  # Set when the bike rejected the request


def parse_message(data: bytes | bytearray) -> ParsedMessage:
    """
    Parse raw bytes from CHAR_NOTIFY or CHAR_REQUEST_READ (TCU1 format).

    Format: [sender: 1B] [channel: 1B] [data: 1-4B little-endian]

    TCX2+ bikes wrap responses in a 20-byte CRC-framed packet.  If a valid
    CRC frame is detected, it is stripped automatically so TCU1-style
    sender/channel parsing can proceed on the inner payload.

    If the inner payload is a NAK (starts with ``f8 ff``), a NAK-flagged
    :class:`ParsedMessage` is returned with ``field_name=None`` and
    ``nak_reason`` set.

    Raises ValueError if data is shorter than 3 bytes.
    """
    from .framing import is_framed_packet, is_nak_packet, parse_nak_packet

    # Detect 20-byte CRC-framed format used by TCX2+ bikes
    if is_framed_packet(data):
        data = data[:-2]  # strip 2-byte CRC trailer

    # NAK rejection from the bike — surface the reason rather than
    # parsing the rejection bytes as if they were valid data.
    if is_nak_packet(data):
        echoed_param, reason = parse_nak_packet(data)
        return ParsedMessage(
            sender=data[0],
            channel=data[1],
            raw_value=echoed_param,
            converted_value=None,
            field_name=None,
            unit="",
            nak_reason=reason,
        )

    if len(data) < 3:
        raise ValueError(f"Message too short ({len(data)} bytes), need at least 3")

    sender = data[0]
    channel = data[1]

    # TCU1 bikes pad notifications to 20 bytes with 0xFF.  Strip trailing
    # padding so field extraction uses only the real data bytes.
    payload = data[2:]
    payload = payload.rstrip(b"\xff")

    # No real data bytes after stripping → field has no value available.
    if len(payload) == 0:
        field_def = get_field_def(sender, channel)
        return ParsedMessage(
            sender=sender,
            channel=channel,
            raw_value=0,
            converted_value=None,
            field_name=field_def.name if field_def else None,
            unit=field_def.unit if field_def else "",
        )

    field_def = get_field_def(sender, channel)

    if field_def is not None:
        # Use the smaller of defined size vs actual payload to avoid
        # reading into padding on TCU1 (e.g. peak_assist is 3 bytes on
        # TCX but only 1 byte per message on TCU1).
        actual_size = min(field_def.data_size, len(payload))
        raw = _int_from_bytes(payload, 0, actual_size)
        converted = field_def.convert(raw)
        return ParsedMessage(
            sender=sender,
            channel=channel,
            raw_value=raw,
            converted_value=converted,
            field_name=field_def.name,
            unit=field_def.unit,
        )
    else:
        # Unknown field — extract as many bytes as available
        raw = _int_from_bytes(payload, 0, len(payload))
        return ParsedMessage(
            sender=sender,
            channel=channel,
            raw_value=raw,
            converted_value=raw,
            field_name=None,
            unit="",
        )


def is_specialized_advertisement(
    manufacturer_data: dict[int, bytes],
    *,
    local_name: str | None = None,
    service_uuids: Iterable[str] | None = None,
) -> bool:
    """
    Check if BLE manufacturer data belongs to a Specialized Turbo bike.

    Detects both TCX (Nordic company ID + TURBOHMI magic) and
    TCU1 (Simplo Technology company ID) bikes.
    """
    return (
        parse_bike_advertisement(
            manufacturer_data,
            local_name=local_name,
            service_uuids=service_uuids,
        )
        is not None
    )


def parse_bike_advertisement(
    manufacturer_data: dict[int, bytes],
    *,
    local_name: str | None = None,
    service_uuids: Iterable[str] | None = None,
) -> BikeAdvertisement | None:
    """Decode Specialized protocol metadata from BLE manufacturer data."""
    nordic_payload = manufacturer_data.get(NORDIC_COMPANY_ID)
    if nordic_payload is not None:
        has_specialized_identity = (
            isinstance(local_name, str)
            and _SPECIALIZED_NAME_PATTERN.fullmatch(local_name) is not None
        ) or any(
            isinstance(uuid, str) and uuid.lower() in _TCX_SERVICE_UUIDS
            for uuid in service_uuids or ()
        )
        if len(nordic_payload) == 10 and has_specialized_identity:
            return BikeAdvertisement(
                generation=BLEProfile.TCX,
                encryption=ProtocolEncryptionMethod.AES_CTR,
                hmi_serial=str(int.from_bytes(nordic_payload[:4], "little")),
                hmi_hardware=".".join(chr(value) for value in nordic_payload[4:7]),
                reserved=nordic_payload[7],
                bike_type=nordic_payload[8],
                system_state=nordic_payload[9],
            )
        if ADVERTISING_MAGIC in nordic_payload:
            return BikeAdvertisement(generation=BLEProfile.TCX)

    apple_payload = manufacturer_data.get(APPLE_COMPANY_ID)
    if apple_payload is not None and ADVERTISING_MAGIC in apple_payload:
        return BikeAdvertisement(generation=BLEProfile.TCX)

    for company_id, payload in manufacturer_data.items():
        if (
            company_id not in {NORDIC_COMPANY_ID, APPLE_COMPANY_ID}
            and ADVERTISING_MAGIC in payload
        ):
            return BikeAdvertisement(generation=BLEProfile.TCX)

    if SIMPLO_COMPANY_ID in manufacturer_data:
        return BikeAdvertisement(generation=BLEProfile.TCU1)

    return None


def detect_generation(
    manufacturer_data: dict[int, bytes],
    *,
    local_name: str | None = None,
    service_uuids: Iterable[str] | None = None,
) -> BLEProfile | None:
    """
    Determine the protocol generation from BLE manufacturer advertisement data.

    Returns ``BLEProfile.TCX`` for Nordic/TURBOHMI advertisements,
    ``BLEProfile.TCU1`` for Simplo Technology advertisements,
    or ``None`` if the data does not match a known Specialized bike.
    """
    advertisement = parse_bike_advertisement(
        manufacturer_data,
        local_name=local_name,
        service_uuids=service_uuids,
    )
    return advertisement.generation if advertisement is not None else None


# ---------------------------------------------------------------------------
# Command builders
# ---------------------------------------------------------------------------


def build_request(sender: int, channel: int) -> bytes:
    """Build the 2-byte query payload for CHAR_REQUEST_WRITE (TCU1 format)."""
    return bytes([sender, channel])


def build_tcx_request(param_id: int) -> bytes:
    """Build the 2-byte payload for a TCX2+ notification-backed query."""
    from .parameters import encode_parameter_id

    return encode_parameter_id(param_id)


def build_write_command(sender: int, channel: int, data: bytes | bytearray) -> bytes:
    """
    Build a TCU1 write command: ``[sender, channel, data...]``.

    Written to the TCU1 command characteristic.  Example::

        build_write_command(0x01, 0x05, bytes([2]))  # set assist to TRAIL
    """
    return bytes([sender, channel]) + bytes(data)


def build_tcx_write(param_id: int, data: bytes | bytearray) -> bytes:
    """
    Build a TCX2+ write command: ``[param_id_be, data...]``.

    The result should be passed through ``session.pack()`` before writing
    without response to the service 3 write characteristic.  Example::

        build_tcx_write(143, bytes([2]))  # set travel mode
    """
    from .parameters import encode_parameter_id

    return encode_parameter_id(param_id) + bytes(data)


# ---------------------------------------------------------------------------
# TCX message parsing
# ---------------------------------------------------------------------------


def parse_tcx_message(data: bytes | bytearray) -> ParsedMessage:
    """
    Parse a TCX2/TCX3/TCX4 message (after CRC/encryption stripping).

    Format: [param_id_hi: 1B] [param_id_lo: 1B] [data: 0-16B little-endian]

    If the message is a NAK (starts with ``f8 ff``), a NAK-flagged
    :class:`ParsedMessage` is returned with ``field_name=None`` and
    ``nak_reason`` set to the rejection code from the bike.  Earlier
    versions of this library stripped the ``f8 ff`` prefix and parsed the
    rejection code as if it were valid data, producing bogus telemetry.

    .. note::
       **Legacy parser.** This treats the 2-byte header directly as a
       :class:`~parameters.BikeParameter` value, which is only correct when a
       parameter's wire id happens to equal its ``BikeParameter`` id.  On real
       generation/revision-aware bikes the two id spaces differ; use the
       profile-aware :func:`specialized_turbo.identification.parse_wire_message`
       (which reverse-maps the wire id via
       :mod:`specialized_turbo.wire_profiles`) instead.  This function is kept
       for the existing telemetry paths that still address parameters by their
       enum id.
    """
    from .framing import is_nak_packet, parse_nak_packet
    from .parameters import decode_parameter_id, get_tcx_field

    if len(data) < 2:
        raise ValueError(f"TCX message too short ({len(data)} bytes), need at least 2")

    # NAK rejection from the bike.  Surface the echoed parameter ID and
    # reason code; do not attempt to decode the remaining bytes as data.
    if is_nak_packet(data):
        echoed_param, reason = parse_nak_packet(data)
        return ParsedMessage(
            sender=0xF8,
            channel=0xFF,
            raw_value=echoed_param,
            converted_value=None,
            field_name=None,
            unit="",
            nak_reason=reason,
        )

    param_id = decode_parameter_id(data)
    payload = data[2:]

    # Strip trailing zero-padding (TCX pads to 18 bytes total)
    payload = payload.rstrip(b"\x00")

    field_def = get_tcx_field(param_id)

    if len(payload) == 0:
        return ParsedMessage(
            sender=param_id >> 8,
            channel=param_id & 0xFF,
            raw_value=0,
            converted_value=None,
            field_name=field_def.name if field_def else None,
            unit=field_def.unit if field_def else "",
        )

    if field_def is not None:
        actual_size = min(field_def.data_size, len(payload))
        raw = _int_from_bytes(payload, 0, actual_size)
        converted = field_def.convert(raw)
        return ParsedMessage(
            sender=param_id >> 8,
            channel=param_id & 0xFF,
            raw_value=raw,
            converted_value=converted,
            field_name=field_def.name,
            unit=field_def.unit,
        )

    # Unknown parameter — extract as many bytes as available
    raw = _int_from_bytes(payload, 0, len(payload))
    return ParsedMessage(
        sender=param_id >> 8,
        channel=param_id & 0xFF,
        raw_value=raw,
        converted_value=raw,
        field_name=None,
        unit="",
    )


# ---------------------------------------------------------------------------
# TCU1 polling
# ---------------------------------------------------------------------------

# Fields to poll via request-read on TCU1 bikes. TCU1 pushes very few
# fields passively (peak_assist cycles constantly, temps and voltage arrive
# infrequently). Poll everything we care about.
TCU1_POLL_FIELDS: tuple[tuple[int, int], ...] = (
    # Battery
    (Sender.BATTERY, BatteryChannel.SIZE_WH),
    (Sender.BATTERY, BatteryChannel.REMAIN_WH),
    (Sender.BATTERY, BatteryChannel.HEALTH),
    (Sender.BATTERY, BatteryChannel.TEMP),
    (Sender.BATTERY, BatteryChannel.CHARGE_CYCLES),
    (Sender.BATTERY, BatteryChannel.VOLTAGE),
    (Sender.BATTERY, BatteryChannel.CURRENT),
    (Sender.BATTERY, BatteryChannel.CHARGE_PERCENT),
    # Motor / rider
    (Sender.MOTOR, MotorChannel.RIDER_POWER),
    (Sender.MOTOR, MotorChannel.CADENCE),
    (Sender.MOTOR, MotorChannel.SPEED),
    (Sender.MOTOR, MotorChannel.ODOMETER),
    (Sender.MOTOR, MotorChannel.ASSIST_LEVEL),
    (Sender.MOTOR, MotorChannel.MOTOR_TEMP),
    (Sender.MOTOR, MotorChannel.MOTOR_POWER),
)
