"""
Data models for bike telemetry.

Mutable dataclass containers that accumulate decoded BLE messages
into a snapshot of the bike's current state.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, fields as dc_fields
from typing import Any, ClassVar

from .protocol import (
    AssistLevel,
    ParsedMessage,
    Sender,
    BatteryChannel,
    MotorChannel,
    BikeSettingsChannel,
)


def _non_none_fields(obj: Any) -> dict[str, Any]:
    """Return a dict of non-None dataclass instance fields."""
    return {
        f.name: getattr(obj, f.name)
        for f in dc_fields(obj)
        if getattr(obj, f.name) is not None
    }


@dataclass(slots=True)
class BatteryState:
    """Snapshot of a single battery pack."""

    capacity_wh: float | None = None
    remaining_wh: float | None = None
    health_pct: int | None = None
    temp_c: int | None = None
    charge_cycles: int | None = None
    voltage_v: float | None = None
    current_a: float | None = None
    charge_pct: int | None = None

    _CHANNEL_MAP: ClassVar[dict[int, str]] = {
        BatteryChannel.SIZE_WH: "capacity_wh",
        BatteryChannel.REMAIN_WH: "remaining_wh",
        BatteryChannel.HEALTH: "health_pct",
        BatteryChannel.TEMP: "temp_c",
        BatteryChannel.CHARGE_CYCLES: "charge_cycles",
        BatteryChannel.VOLTAGE: "voltage_v",
        BatteryChannel.CURRENT: "current_a",
        BatteryChannel.CHARGE_PERCENT: "charge_pct",
    }

    def update(self, channel: int, value: Any) -> bool:
        """Update a field from a parsed message. Returns True if field was known."""
        attr = self._CHANNEL_MAP.get(channel)
        if attr is not None:
            setattr(self, attr, value)
            return True
        return False

    def as_dict(self) -> dict[str, Any]:
        return _non_none_fields(self)


@dataclass(slots=True)
class MotorState:
    """Snapshot of motor and rider data."""

    rider_power_w: float | None = None
    cadence_rpm: float | None = None
    speed_kmh: float | None = None
    odometer_km: float | None = None
    assist_level: AssistLevel | int | None = None
    motor_temp_c: int | None = None
    motor_power_w: float | None = None
    peak_assist: tuple[int, int, int] | None = None
    shuttle: int | None = None
    max_speed_limit_kmh: float | None = None

    _CHANNEL_MAP: ClassVar[dict[int, str]] = {
        MotorChannel.RIDER_POWER: "rider_power_w",
        MotorChannel.CADENCE: "cadence_rpm",
        MotorChannel.SPEED: "speed_kmh",
        MotorChannel.ODOMETER: "odometer_km",
        MotorChannel.ASSIST_LEVEL: "assist_level",
        MotorChannel.MOTOR_TEMP: "motor_temp_c",
        MotorChannel.MOTOR_POWER: "motor_power_w",
        MotorChannel.PEAK_ASSIST: "peak_assist",
        MotorChannel.SHUTTLE: "shuttle",
    }

    def update(self, channel: int, value: Any) -> bool:
        """Update a field from a parsed message. Returns True if field was known."""
        attr = self._CHANNEL_MAP.get(channel)
        if attr is not None:
            setattr(self, attr, value)
            return True
        return False

    def as_dict(self) -> dict[str, Any]:
        result = _non_none_fields(self)
        if isinstance(result.get("assist_level"), AssistLevel):
            result["assist_level"] = result["assist_level"].name
        return result


@dataclass(slots=True)
class BikeSettings:
    """Snapshot of bike configuration values."""

    wheel_circumference_mm: int | None = None
    assist_lev1_pct: int | None = None
    assist_lev2_pct: int | None = None
    assist_lev3_pct: int | None = None
    fake_channel: int | None = None
    acceleration_pct: float | None = None

    _CHANNEL_MAP: ClassVar[dict[int, str]] = {
        BikeSettingsChannel.WHEEL_CIRCUMFERENCE: "wheel_circumference_mm",
        BikeSettingsChannel.ASSIST_LEV1: "assist_lev1_pct",
        BikeSettingsChannel.ASSIST_LEV2: "assist_lev2_pct",
        BikeSettingsChannel.ASSIST_LEV3: "assist_lev3_pct",
        BikeSettingsChannel.FAKE_CHANNEL: "fake_channel",
        BikeSettingsChannel.ACCELERATION: "acceleration_pct",
    }

    def update(self, channel: int, value: Any) -> bool:
        """Update a field from a parsed message. Returns True if field was known."""
        attr = self._CHANNEL_MAP.get(channel)
        if attr is not None:
            setattr(self, attr, value)
            return True
        return False

    def as_dict(self) -> dict[str, Any]:
        return _non_none_fields(self)


@dataclass(slots=True)
class SystemState:
    """TCX2+ system-level telemetry (range, altitude, consumption, etc.).

    Unlike BatteryState/MotorState/BikeSettings, this model has no
    ``_CHANNEL_MAP`` or ``update()`` method.  It is populated exclusively
    through the field-name routing in ``TelemetrySnapshot._FIELD_NAME_MAP``
    and is only relevant for TCX2+ bikes.
    """

    range_long_km: float | None = None
    range_short_km: float | None = None
    range_trend: int | None = None
    system_temp_c: int | None = None
    consumption_wh_km: float | None = None
    kcal: int | None = None
    altitude_m: int | None = None
    altitude_gain_m: int | None = None
    altitude_descent_m: int | None = None
    gradient_pct: float | None = None
    system_state: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return _non_none_fields(self)


@dataclass(slots=True)
class TelemetrySnapshot:
    """
    All bike telemetry in one place, updated as BLE notifications come in.

    Each notification updates the relevant sub-model (battery, motor, settings).
    Read fields directly off .battery, .motor, etc.
    """

    battery: BatteryState = field(default_factory=BatteryState)
    battery2: BatteryState = field(default_factory=BatteryState)
    motor: MotorState = field(default_factory=MotorState)
    settings: BikeSettings = field(default_factory=BikeSettings)
    system: SystemState = field(default_factory=SystemState)
    last_updated: float = field(default_factory=time.monotonic)
    message_count: int = 0
    unknown_messages: list[ParsedMessage] = field(default_factory=list, repr=False)

    # Maps TCX field names (from parse_tcx_message) to (sub_model, attribute).
    # Used as a fallback when sender/channel routing doesn't match (TCX2+ bikes).
    _FIELD_NAME_MAP: ClassVar[dict[str, tuple[str, str]]] = {
        # Battery 1
        "battery_charge_percent": ("battery", "charge_pct"),
        "battery_temp": ("battery", "temp_c"),
        "battery_voltage": ("battery", "voltage_v"),
        "battery_current": ("battery", "current_a"),
        "battery_health": ("battery", "health_pct"),
        "battery_capacity_wh": ("battery", "capacity_wh"),
        "battery_remaining_wh": ("battery", "remaining_wh"),
        "battery_charge_cycles": ("battery", "charge_cycles"),
        # Battery 2
        "battery2_charge_percent": ("battery2", "charge_pct"),
        "battery2_temp": ("battery2", "temp_c"),
        "battery2_voltage": ("battery2", "voltage_v"),
        "battery2_current": ("battery2", "current_a"),
        "battery2_health": ("battery2", "health_pct"),
        "battery2_capacity_wh": ("battery2", "capacity_wh"),
        "battery2_remaining_wh": ("battery2", "remaining_wh"),
        "battery2_charge_cycles": ("battery2", "charge_cycles"),
        # Motor / rider
        "cadence": ("motor", "cadence_rpm"),
        "speed": ("motor", "speed_kmh"),
        "odometer": ("motor", "odometer_km"),
        "motor_power": ("motor", "motor_power_w"),
        "rider_power": ("motor", "rider_power_w"),
        "motor_temp": ("motor", "motor_temp_c"),
        "assist_level": ("motor", "assist_level"),
        # Settings
        "wheel_circumference": ("settings", "wheel_circumference_mm"),
        "acceleration": ("settings", "acceleration_pct"),
        # Motor (TCX-only)
        "max_speed_limit": ("motor", "max_speed_limit_kmh"),
        # System (TCX-only)
        "range_long": ("system", "range_long_km"),
        "range_short": ("system", "range_short_km"),
        "range_trend": ("system", "range_trend"),
        "system_temp": ("system", "system_temp_c"),
        "consumption": ("system", "consumption_wh_km"),
        "kcal": ("system", "kcal"),
        "altitude": ("system", "altitude_m"),
        "altitude_gain": ("system", "altitude_gain_m"),
        "altitude_descent": ("system", "altitude_descent_m"),
        "gradient": ("system", "gradient_pct"),
        "system_state": ("system", "system_state"),
    }

    def update_from_message(self, msg: ParsedMessage) -> None:
        """Route a parsed message to the right sub-model.

        TCU1 messages route by sender/channel. TCX2+ messages (from
        ``parse_tcx_message``) route by field name as a fallback when
        the sender/channel doesn't match a known sub-model.
        """
        self.last_updated = time.monotonic()
        self.message_count += 1

        sender = msg.sender
        channel = msg.channel
        value = msg.converted_value

        # Skip sentinel values (all-bits-set = "not available")
        if value is None:
            return

        # Try sender/channel routing (TCU1 path)
        if sender == Sender.BATTERY:
            if self.battery.update(channel, value):
                return
        elif sender == Sender.BATTERY_2:
            if self.battery2.update(channel, value):
                return
        elif sender == Sender.MOTOR:
            if self.motor.update(channel, value):
                return
        elif sender == Sender.BIKE_SETTINGS:
            if self.settings.update(channel, value):
                return

        # Fall through to field-name routing (TCX2+ path)
        if msg.field_name is not None:
            route = self._FIELD_NAME_MAP.get(msg.field_name)
            if route is not None:
                sub_model_name, attr = route
                sub_model = getattr(self, sub_model_name)
                setattr(sub_model, attr, value)
                return

        self.unknown_messages.append(msg)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary of all known values."""
        result: dict[str, Any] = {}
        result["battery"] = self.battery.as_dict()
        batt2 = self.battery2.as_dict()
        if batt2:
            result["battery2"] = batt2
        result["motor"] = self.motor.as_dict()
        settings = self.settings.as_dict()
        if settings:
            result["settings"] = settings
        system = self.system.as_dict()
        if system:
            result["system"] = system
        result["message_count"] = self.message_count
        return result
