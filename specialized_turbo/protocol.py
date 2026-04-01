"""
Specialized Turbo BLE protocol.

UUIDs, message format, enums, and parsing. Ported from the
Sepp62/LevoEsp32Ble C++ project (MIT).

Supports two protocol generations:
- Gen 2 ("TURBOHMI2017"): Vado/Levo/Creo 2019+, Nordic manufacturer ID
- Gen 1 ("GIGATRONIK"): Levo 2018, Simplo manufacturer ID

Both generations share the same message format and field definitions;
only the BLE UUIDs and advertisement data differ.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Callable, NamedTuple

# ---------------------------------------------------------------------------
# Protocol generation
# ---------------------------------------------------------------------------


class ProtocolGeneration(StrEnum):
    """BLE protocol generation for Specialized Turbo bikes."""

    GEN_1 = "gen1"  # 2018 Levo (Gigatronik TCU, Simplo mfr ID)
    GEN_2 = "gen2"  # 2019+ Vado/Levo/Creo (TURBOHMI2017, Nordic mfr ID)


# ---------------------------------------------------------------------------
# UUID definitions
# ---------------------------------------------------------------------------

# Gen 2 base UUID: 000000xx-3731-3032-494d-484f42525554
# Last 12 bytes = "7102IMHOBRUT" = reverse of "TURBOHMI2017"
GEN2_UUID_BASE = "0000{:04x}-3731-3032-494d-484f42525554"

# Gen 1 base UUID: 000000xx-0000-4b49-4e4f-525441474947
# Last 10 bytes = "KINORTAGIG" = reverse of "GIGATRONIK"
GEN1_UUID_BASE = "0000{:04x}-0000-4b49-4e4f-525441474947"

# Backward-compatible alias (Gen 2)
UUID_BASE = GEN2_UUID_BASE

_UUID_BASES: dict[ProtocolGeneration, str] = {
    ProtocolGeneration.GEN_1: GEN1_UUID_BASE,
    ProtocolGeneration.GEN_2: GEN2_UUID_BASE,
}


def _uuid(short: int) -> str:
    """Expand a short UUID into the full 128-bit Gen 2 UUID."""
    return GEN2_UUID_BASE.format(short)


def _uuid_gen1(short: int) -> str:
    """Expand a short UUID into the full 128-bit Gen 1 UUID."""
    return GEN1_UUID_BASE.format(short)


def get_uuid(generation: ProtocolGeneration, short: int) -> str:
    """Expand a short UUID for the given protocol generation."""
    return _UUID_BASES[generation].format(short)


# ------ Gen 2 UUIDs (default, backward-compatible) ------

# Service UUIDs
SERVICE_DATA_NOTIFY = _uuid(0x0003)  # Notification data service
SERVICE_DATA_REQUEST = _uuid(0x0001)  # Request-read service
SERVICE_DATA_WRITE = _uuid(0x0002)  # Write command service

# Characteristic UUIDs
CHAR_NOTIFY = _uuid(0x0013)  # READ, NOTIFY — bike pushes telemetry here
CHAR_REQUEST_WRITE = _uuid(0x0021)  # WRITE — send a 2-byte request here
CHAR_REQUEST_READ = _uuid(0x0011)  # READ — read the response after writing to 0x0021
CHAR_WRITE = _uuid(0x0012)  # WRITE — send commands (assist level, settings)

# ------ Gen 1 UUIDs ------

SERVICE_DATA_NOTIFY_GEN1 = _uuid_gen1(0x0003)
SERVICE_DATA_REQUEST_GEN1 = _uuid_gen1(0x0001)
SERVICE_DATA_WRITE_GEN1 = _uuid_gen1(0x0002)

CHAR_NOTIFY_GEN1 = _uuid_gen1(0x0013)
CHAR_REQUEST_WRITE_GEN1 = _uuid_gen1(0x0021)
CHAR_REQUEST_READ_GEN1 = _uuid_gen1(0x0011)
CHAR_WRITE_GEN1 = _uuid_gen1(0x0012)

# ------ Generation → UUID lookup ------

_CHAR_NOTIFY_MAP: dict[ProtocolGeneration, str] = {
    ProtocolGeneration.GEN_1: CHAR_NOTIFY_GEN1,
    ProtocolGeneration.GEN_2: CHAR_NOTIFY,
}

_CHAR_REQUEST_READ_MAP: dict[ProtocolGeneration, str] = {
    ProtocolGeneration.GEN_1: CHAR_REQUEST_READ_GEN1,
    ProtocolGeneration.GEN_2: CHAR_REQUEST_READ,
}

_CHAR_REQUEST_WRITE_MAP: dict[ProtocolGeneration, str] = {
    ProtocolGeneration.GEN_1: CHAR_REQUEST_WRITE_GEN1,
    ProtocolGeneration.GEN_2: CHAR_REQUEST_WRITE,
}

_CHAR_WRITE_MAP: dict[ProtocolGeneration, str] = {
    ProtocolGeneration.GEN_1: CHAR_WRITE_GEN1,
    ProtocolGeneration.GEN_2: CHAR_WRITE,
}


def get_char_notify(generation: ProtocolGeneration) -> str:
    """Return the CHAR_NOTIFY UUID for the given protocol generation."""
    return _CHAR_NOTIFY_MAP[generation]


def get_char_request_read(generation: ProtocolGeneration) -> str:
    """Return the CHAR_REQUEST_READ UUID for the given protocol generation."""
    return _CHAR_REQUEST_READ_MAP[generation]


def get_char_request_write(generation: ProtocolGeneration) -> str:
    """Return the CHAR_REQUEST_WRITE UUID for the given protocol generation."""
    return _CHAR_REQUEST_WRITE_MAP[generation]


def get_char_write(generation: ProtocolGeneration) -> str:
    """Return the CHAR_WRITE UUID for the given protocol generation."""
    return _CHAR_WRITE_MAP[generation]


# ---------------------------------------------------------------------------
# BLE company IDs
# ---------------------------------------------------------------------------

# Nordic Semiconductor (Gen 2 bikes)
NORDIC_COMPANY_ID = 0x0059

# Simplo Technology Co., LTD (Gen 1 bikes)
SIMPLO_COMPANY_ID = 0x020D

# Magic advertising string embedded in Gen 2 manufacturer data
ADVERTISING_MAGIC = b"TURBOHMI"

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


@dataclass(frozen=True, slots=True)
class FieldDefinition:
    """Metadata for a single protocol field."""

    sender: int
    channel: int
    name: str
    unit: str
    data_size: int  # bytes of payload (after sender+channel)
    convert: Callable[[int], float | int]

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
) -> FieldDefinition:
    if convert is None:
        convert = lambda v: v  # noqa: E731  identity
    fd = FieldDefinition(
        sender=sender,
        channel=channel,
        name=name,
        unit=unit,
        data_size=size,
        convert=convert,
    )
    _FIELD_DEFS[fd.key] = fd
    return fd


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
)
_reg(0x01, 0x07, "motor_temp", "°C", 1)
_reg(0x01, 0x0C, "motor_power", "W", 2)
_reg(0x01, 0x10, "peak_assist", "", 3)  # 3 bytes: ECO%, TRAIL%, TURBO%
_reg(0x01, 0x15, "shuttle", "", 1)

# --- Bike settings fields (sender 0x02) ---
_reg(0x02, 0x00, "wheel_circumference", "mm", 2)
_reg(0x02, 0x03, "assist_lev1_pct", "%", 1)
_reg(0x02, 0x04, "assist_lev2_pct", "%", 1)
_reg(0x02, 0x05, "assist_lev3_pct", "%", 1)
_reg(0x02, 0x06, "fake_channel", "", 1)
_reg(0x02, 0x07, "acceleration", "%", 2, lambda v: (v - 3000) / 60.0)

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
    field_name: str | None  # None if field is unknown
    unit: str


def parse_message(data: bytes | bytearray) -> ParsedMessage:
    """
    Parse raw bytes from CHAR_NOTIFY or CHAR_REQUEST_READ.

    Format: [sender: 1B] [channel: 1B] [data: 1-4B little-endian]

    Raises ValueError if data is shorter than 3 bytes.
    """
    if len(data) < 3:
        raise ValueError(f"Message too short ({len(data)} bytes), need at least 3")

    sender = data[0]
    channel = data[1]

    # Gen 1 bikes pad notifications to 20 bytes with 0xFF.  Strip trailing
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
        # reading into padding on Gen 1 (e.g. peak_assist is 3 bytes on
        # Gen 2 but only 1 byte per message on Gen 1).
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


def is_specialized_advertisement(manufacturer_data: dict[int, bytes]) -> bool:
    """
    Check if BLE manufacturer data belongs to a Specialized Turbo bike.

    Detects both Gen 2 (Nordic company ID + TURBOHMI magic) and
    Gen 1 (Simplo Technology company ID) bikes.
    """
    return detect_generation(manufacturer_data) is not None


def detect_generation(
    manufacturer_data: dict[int, bytes],
) -> ProtocolGeneration | None:
    """
    Determine the protocol generation from BLE manufacturer advertisement data.

    Returns ``ProtocolGeneration.GEN_2`` for Nordic/TURBOHMI advertisements,
    ``ProtocolGeneration.GEN_1`` for Simplo Technology advertisements,
    or ``None`` if the data does not match a known Specialized bike.
    """
    # Gen 2: Nordic company ID with TURBOHMI magic
    payload = manufacturer_data.get(NORDIC_COMPANY_ID)
    if payload is not None and ADVERTISING_MAGIC in payload:
        return ProtocolGeneration.GEN_2
    # Gen 1: Simplo Technology company ID
    if SIMPLO_COMPANY_ID in manufacturer_data:
        return ProtocolGeneration.GEN_1
    return None


# ---------------------------------------------------------------------------
# Command builders
# ---------------------------------------------------------------------------


def build_request(sender: int, channel: int) -> bytes:
    """Build the 2-byte query payload for CHAR_REQUEST_WRITE."""
    return bytes([sender, channel])
