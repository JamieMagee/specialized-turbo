"""
Unit tests for models.py — TelemetrySnapshot and sub-models.
"""

import pytest

from specialized_turbo.models import (
    BatteryState,
    BikeSettings,
    MotorState,
    TelemetrySnapshot,
)
from specialized_turbo.protocol import (
    AssistLevel,
    BatteryChannel,
    BikeSettingsChannel,
    MotorChannel,
    ParsedMessage,
    parse_message,
)


class TestBatteryState:
    def test_update_charge_percent(self):
        batt = BatteryState()
        assert batt.charge_pct is None
        batt.update(BatteryChannel.CHARGE_PERCENT, 85)
        assert batt.charge_pct == 85

    def test_update_all_channels(self):
        batt = BatteryState()
        batt.update(BatteryChannel.SIZE_WH, 500)
        batt.update(BatteryChannel.REMAIN_WH, 350)
        batt.update(BatteryChannel.HEALTH, 98)
        batt.update(BatteryChannel.TEMP, 22)
        batt.update(BatteryChannel.CHARGE_CYCLES, 45)
        batt.update(BatteryChannel.VOLTAGE, 36.0)
        batt.update(BatteryChannel.CURRENT, 5.0)
        batt.update(BatteryChannel.CHARGE_PERCENT, 70)

        d = batt.as_dict()
        assert d["capacity_wh"] == 500
        assert d["remaining_wh"] == 350
        assert d["health_pct"] == 98
        assert d["temp_c"] == 22
        assert d["charge_cycles"] == 45
        assert d["voltage_v"] == 36.0
        assert d["current_a"] == 5.0
        assert d["charge_pct"] == 70

    def test_update_unknown_channel_returns_false(self):
        batt = BatteryState()
        assert batt.update(0xFF, 42) is False

    def test_as_dict_excludes_none(self):
        batt = BatteryState()
        batt.update(BatteryChannel.CHARGE_PERCENT, 50)
        d = batt.as_dict()
        assert "charge_pct" in d
        assert "capacity_wh" not in d


class TestMotorState:
    def test_update_speed(self):
        motor = MotorState()
        motor.update(MotorChannel.SPEED, 22.5)
        assert motor.speed_kmh == 22.5

    def test_update_assist_level(self):
        motor = MotorState()
        motor.update(MotorChannel.ASSIST_LEVEL, AssistLevel.TURBO)
        assert motor.assist_level == AssistLevel.TURBO

    def test_as_dict_assist_uses_name(self):
        motor = MotorState()
        motor.update(MotorChannel.ASSIST_LEVEL, AssistLevel.ECO)
        motor.update(MotorChannel.SPEED, 15.0)
        d = motor.as_dict()
        assert d["assist_level"] == "ECO"
        assert d["speed_kmh"] == 15.0


class TestBikeSettings:
    def test_update_wheel_circ(self):
        s = BikeSettings()
        s.update(BikeSettingsChannel.WHEEL_CIRCUMFERENCE, 2300)
        assert s.wheel_circumference_mm == 2300

    def test_update_assist_levels(self):
        s = BikeSettings()
        s.update(BikeSettingsChannel.ASSIST_LEV1, 10)
        s.update(BikeSettingsChannel.ASSIST_LEV2, 20)
        s.update(BikeSettingsChannel.ASSIST_LEV3, 50)
        assert s.assist_lev1_pct == 10
        assert s.assist_lev2_pct == 20
        assert s.assist_lev3_pct == 50


class TestTelemetrySnapshot:
    def test_update_routes_battery(self):
        snap = TelemetrySnapshot()
        msg = parse_message(bytes.fromhex("000c34"))  # battery charge 52%
        snap.update_from_message(msg)
        assert snap.battery.charge_pct == 52
        assert snap.message_count == 1

    def test_update_routes_motor(self):
        snap = TelemetrySnapshot()
        msg = parse_message(bytes.fromhex("0102fa00"))  # speed = 25.0 km/h
        snap.update_from_message(msg)
        assert snap.motor.speed_kmh == pytest.approx(25.0)

    def test_update_routes_settings(self):
        snap = TelemetrySnapshot()
        msg = parse_message(bytes.fromhex("0200fc08"))  # wheel circ = 2300 mm
        snap.update_from_message(msg)
        assert snap.settings.wheel_circumference_mm == 2300

    def test_update_routes_secondary_battery(self):
        snap = TelemetrySnapshot()
        msg = parse_message(bytes.fromhex("040c50"))  # battery2 charge = 80%
        snap.update_from_message(msg)
        assert snap.battery2.charge_pct == 80

    def test_unknown_sender_stored(self):
        snap = TelemetrySnapshot()
        msg = parse_message(bytes.fromhex("030042"))  # sender 0x03 = unknown
        snap.update_from_message(msg)
        assert len(snap.unknown_messages) == 1

    def test_message_count_increments(self):
        snap = TelemetrySnapshot()
        for hex_data in ["000c34", "010719", "0102fa00"]:
            snap.update_from_message(parse_message(bytes.fromhex(hex_data)))
        assert snap.message_count == 3

    def test_as_dict_complete(self):
        snap = TelemetrySnapshot()
        snap.update_from_message(parse_message(bytes.fromhex("000c34")))  # battery 52%
        snap.update_from_message(parse_message(bytes.fromhex("0102fa00")))  # speed 25
        snap.update_from_message(
            parse_message(bytes.fromhex("01050200"))
        )  # assist TRAIL

        d = snap.as_dict()
        assert d["battery"]["charge_pct"] == 52
        assert d["motor"]["speed_kmh"] == pytest.approx(25.0)
        assert d["motor"]["assist_level"] == "TRAIL"
        assert d["message_count"] == 3

    def test_as_dict_excludes_empty_battery2(self):
        snap = TelemetrySnapshot()
        snap.update_from_message(parse_message(bytes.fromhex("000c34")))
        d = snap.as_dict()
        assert "battery2" not in d

    def test_sentinel_values_not_stored(self):
        """All-0xFF (stripped) values should not update snapshot fields."""
        snap = TelemetrySnapshot()
        # Send cadence with all-0xFF payload (stripped to empty → None)
        snap.update_from_message(parse_message(bytes.fromhex("0101ffff")))
        assert snap.motor.cadence_rpm is None
        assert snap.message_count == 1  # message still counted

    def test_sentinel_does_not_overwrite_valid(self):
        """An all-0xFF value should not overwrite a previously valid value."""
        snap = TelemetrySnapshot()
        # Set valid speed first
        snap.update_from_message(parse_message(bytes.fromhex("0102fa00")))  # 25.0 km/h
        assert snap.motor.speed_kmh == pytest.approx(25.0)
        # Now send all-0xFF
        snap.update_from_message(parse_message(bytes.fromhex("0102ffff")))
        assert snap.motor.speed_kmh == pytest.approx(25.0)  # unchanged

    def test_tcu1_mixed_valid_and_stripped(self):
        """Simulate TCU1 scenario: some fields valid, others all-0xFF."""
        snap = TelemetrySnapshot()
        # Valid battery temp (1 byte, not all-FF)
        snap.update_from_message(parse_message(bytes.fromhex("000312")))  # 18°C
        # All-FF cadence
        snap.update_from_message(parse_message(bytes.fromhex("0101ffff")))
        # All-FF speed
        snap.update_from_message(parse_message(bytes.fromhex("0102ffff")))
        # Valid voltage
        snap.update_from_message(parse_message(bytes.fromhex("00055a")))  # 38V

        assert snap.battery.temp_c == 18
        assert snap.battery.voltage_v == pytest.approx(38.0)
        assert snap.motor.cadence_rpm is None
        assert snap.motor.speed_kmh is None
        assert snap.message_count == 4

    def test_tcu1_peak_assist_single_byte(self):
        """TCU1 peak_assist stores single-byte values (not 3-byte tuple)."""
        snap = TelemetrySnapshot()
        # 01 10 1A FF FF... → stripped to 1 byte → raw 0x1A=26
        data = bytes.fromhex("01101A" + "ff" * 17)
        snap.update_from_message(parse_message(data))
        assert snap.motor.peak_assist == 26

    def test_full_scenario(self):
        """Simulate a realistic sequence of messages."""
        snap = TelemetrySnapshot()
        messages = [
            "0000c201",  # battery capacity 500 Wh
            "0001e400",  # battery remaining 253 Wh
            "000264",  # battery health 100%
            "000313",  # battery temp 19°C
            "00040d00",  # charge cycles 13
            "000550",  # voltage 36.0 V
            "000600",  # current 0 A
            "000c34",  # charge 52%
            "0100c800",  # rider power 200 W
            "01012c03",  # cadence 81.2 RPM
            "0102fa00",  # speed 25.0 km/h
            "01050200",  # assist TRAIL
            "010719",  # motor temp 25°C
            "010c6400",  # motor power 100 W
            "0200fc08",  # wheel circ 2300 mm
            "02030a",  # assist lev1 10%
            "020414",  # assist lev2 20%
            "020532",  # assist lev3 50%
        ]

        for hex_data in messages:
            snap.update_from_message(parse_message(bytes.fromhex(hex_data)))

        assert snap.message_count == len(messages)
        assert snap.battery.capacity_wh == 500
        assert snap.battery.remaining_wh == 253
        assert snap.battery.health_pct == 100
        assert snap.battery.temp_c == 19
        assert snap.battery.charge_cycles == 13
        assert snap.battery.voltage_v == pytest.approx(36.0)
        assert snap.battery.current_a == pytest.approx(0.0)
        assert snap.battery.charge_pct == 52
        assert snap.motor.rider_power_w == 200
        assert snap.motor.cadence_rpm == pytest.approx(81.2)
        assert snap.motor.speed_kmh == pytest.approx(25.0)
        assert snap.motor.assist_level == AssistLevel.TRAIL
        assert snap.motor.motor_temp_c == 25
        assert snap.motor.motor_power_w == 100
        assert snap.settings.wheel_circumference_mm == 2300
        assert snap.settings.assist_lev1_pct == 10
        assert snap.settings.assist_lev2_pct == 20
        assert snap.settings.assist_lev3_pct == 50


# ======================================================================
# TCX field-name routing
# ======================================================================


class TestTCXFieldNameRouting:
    """TCX2+ messages route via field_name when sender/channel don't match."""

    def _tcx_msg(self, field_name: str, value: float) -> ParsedMessage:
        """Build a ParsedMessage like parse_tcx_message() would."""

        return ParsedMessage(
            sender=0xFF,  # synthetic sender (won't match any Sender enum)
            channel=0xFF,  # synthetic channel
            raw_value=0,
            converted_value=value,
            field_name=field_name,
            unit="",
        )

    def test_battery_charge_routes_by_name(self):
        snap = TelemetrySnapshot()
        snap.update_from_message(self._tcx_msg("battery_charge_percent", 85))
        assert snap.battery.charge_pct == 85
        assert len(snap.unknown_messages) == 0

    def test_speed_routes_by_name(self):
        snap = TelemetrySnapshot()
        snap.update_from_message(self._tcx_msg("speed", 25.0))
        assert snap.motor.speed_kmh == 25.0

    def test_cadence_routes_by_name(self):
        snap = TelemetrySnapshot()
        snap.update_from_message(self._tcx_msg("cadence", 81.2))
        assert snap.motor.cadence_rpm == pytest.approx(81.2)

    def test_motor_power_routes_by_name(self):
        snap = TelemetrySnapshot()
        snap.update_from_message(self._tcx_msg("motor_power", 200))
        assert snap.motor.motor_power_w == 200

    def test_rider_power_routes_by_name(self):
        snap = TelemetrySnapshot()
        snap.update_from_message(self._tcx_msg("rider_power", 150))
        assert snap.motor.rider_power_w == 150

    def test_battery2_routes_by_name(self):
        snap = TelemetrySnapshot()
        snap.update_from_message(self._tcx_msg("battery2_charge_percent", 60))
        assert snap.battery2.charge_pct == 60

    def test_odometer_routes_by_name(self):
        snap = TelemetrySnapshot()
        snap.update_from_message(self._tcx_msg("odometer", 3789.214))
        assert snap.motor.odometer_km == pytest.approx(3789.214)

    def test_assist_level_routes_by_name(self):
        snap = TelemetrySnapshot()
        snap.update_from_message(self._tcx_msg("assist_level", 2))
        assert snap.motor.assist_level == 2

    def test_wheel_circumference_routes_by_name(self):
        snap = TelemetrySnapshot()
        snap.update_from_message(self._tcx_msg("wheel_circumference", 2300))
        assert snap.settings.wheel_circumference_mm == 2300

    def test_acceleration_routes_by_name(self):
        snap = TelemetrySnapshot()
        snap.update_from_message(self._tcx_msg("acceleration", 20.0))
        assert snap.settings.acceleration_pct == 20.0

    def test_unknown_field_name_goes_to_unknown(self):
        snap = TelemetrySnapshot()
        snap.update_from_message(self._tcx_msg("some_future_field", 42))
        assert len(snap.unknown_messages) == 1

    def test_none_field_name_unknown_sender_goes_to_unknown(self):

        snap = TelemetrySnapshot()
        msg = ParsedMessage(0xFF, 0xFF, 0, 42, None, "")
        snap.update_from_message(msg)
        assert len(snap.unknown_messages) == 1

    def test_tcu1_still_routes_by_sender_channel(self):
        """Existing TCU1 sender/channel routing still works."""
        snap = TelemetrySnapshot()
        msg = parse_message(bytes.fromhex("000c34"))  # battery charge 52%
        snap.update_from_message(msg)
        assert snap.battery.charge_pct == 52
        assert len(snap.unknown_messages) == 0

    def test_mixed_tcu1_and_tcx_messages(self):
        """TCU1 and TCX messages can coexist in the same snapshot."""
        snap = TelemetrySnapshot()
        # TCU1 message
        snap.update_from_message(parse_message(bytes.fromhex("000c34")))
        # TCX message (field-name routed)
        snap.update_from_message(self._tcx_msg("speed", 25.0))
        assert snap.battery.charge_pct == 52
        assert snap.motor.speed_kmh == 25.0
        assert snap.message_count == 2

    def test_parse_tcx_message_integration(self):
        """End-to-end: parse_tcx_message -> update_from_message -> snapshot."""
        from specialized_turbo.protocol import parse_tcx_message

        snap = TelemetrySnapshot()
        # BikeParameter 26 (BATTERY1_STATE_OF_CHARGE) = 0x001A, data = 0x34 (52%)
        payload = b"\x00\x1a\x34" + b"\x00" * 15  # 18 bytes
        msg = parse_tcx_message(payload)
        assert msg.field_name == "battery_charge_percent"
        assert msg.converted_value == 52
        snap.update_from_message(msg)
        assert snap.battery.charge_pct == 52

    def test_parse_tcx_message_with_f8ff_prefix(self):
        """``f8 ff`` is a NAK marker — parse it as a rejection, not as data."""
        from specialized_turbo.protocol import parse_tcx_message

        # Captured Vado 3.0 response: f8ff 016b 05 00...
        # echoed_param=363 (SYSTEM_STATE), reason=0x05.
        payload = bytes.fromhex("f8ff016b050000000000000000000000")
        msg = parse_tcx_message(payload)
        assert msg.nak_reason == 0x05
        assert msg.raw_value == 363  # echoed parameter ID
        assert msg.field_name is None
        assert msg.converted_value is None

    def test_parse_tcx_f8ff_battery_charge(self):
        """A NAK for the battery-charge request does not update the snapshot."""
        from specialized_turbo.protocol import parse_tcx_message

        snap = TelemetrySnapshot()
        # f8ff 001a 34 00... — echoed_param=26 (BATTERY1_STATE_OF_CHARGE),
        # reason=0x34.  Earlier code parsed reason 0x34 as SOC=52%.
        payload = bytes.fromhex("f8ff001a340000000000000000000000")
        msg = parse_tcx_message(payload)
        assert msg.nak_reason == 0x34
        assert msg.raw_value == 26  # echoed parameter ID
        assert msg.field_name is None
        snap.update_from_message(msg)
        # NAK must not produce telemetry — battery state stays empty.
        assert snap.battery.charge_pct is None
