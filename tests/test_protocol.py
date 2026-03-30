"""
Unit tests for protocol.py — message parsing and conversion.

Test vectors are derived from the hex examples in the Sepp62/LevoEsp32Ble
reference implementation and the Micheledv74/turbolevo-pwa dashboard.
"""

import pytest

from specialized_turbo.protocol import (
    AssistLevel,
    BatteryChannel,
    MotorChannel,
    BikeSettingsChannel,
    ProtocolGeneration,
    Sender,
    _uuid,
    _uuid_gen1,
    all_field_defs,
    build_request,
    detect_generation,
    get_char_notify,
    get_field_def,
    get_uuid,
    is_specialized_advertisement,
    parse_message,
    CHAR_NOTIFY,
    CHAR_NOTIFY_GEN1,
    CHAR_REQUEST_READ,
    CHAR_REQUEST_READ_GEN1,
    CHAR_REQUEST_WRITE,
    CHAR_REQUEST_WRITE_GEN1,
    CHAR_WRITE,
    CHAR_WRITE_GEN1,
    SERVICE_DATA_NOTIFY,
    SERVICE_DATA_NOTIFY_GEN1,
    SERVICE_DATA_REQUEST,
    SERVICE_DATA_REQUEST_GEN1,
    SERVICE_DATA_WRITE,
    SERVICE_DATA_WRITE_GEN1,
    NORDIC_COMPANY_ID,
    SIMPLO_COMPANY_ID,
)


# ======================================================================
# UUID generation
# ======================================================================


class TestUUIDs:
    def test_uuid_base_format(self):
        uuid = _uuid(0x0013)
        assert uuid == "00000013-3731-3032-494d-484f42525554"

    def test_service_notify_uuid(self):
        assert SERVICE_DATA_NOTIFY == "00000003-3731-3032-494d-484f42525554"

    def test_service_request_uuid(self):
        assert SERVICE_DATA_REQUEST == "00000001-3731-3032-494d-484f42525554"

    def test_service_write_uuid(self):
        assert SERVICE_DATA_WRITE == "00000002-3731-3032-494d-484f42525554"

    def test_char_notify_uuid(self):
        assert CHAR_NOTIFY == "00000013-3731-3032-494d-484f42525554"

    def test_char_request_write_uuid(self):
        assert CHAR_REQUEST_WRITE == "00000021-3731-3032-494d-484f42525554"

    def test_char_request_read_uuid(self):
        assert CHAR_REQUEST_READ == "00000011-3731-3032-494d-484f42525554"

    def test_char_write_uuid(self):
        assert CHAR_WRITE == "00000012-3731-3032-494d-484f42525554"

    def test_uuid_base_contains_turbohmi(self):
        """Last 12 bytes of UUID base decode to TURBOHMI2017 reversed."""
        uuid = _uuid(0x0000)
        # Extract the parts after the short ID: 3731-3032-494d-484f42525554
        tail_hex = uuid.split("-", 1)[1].replace("-", "")
        tail_bytes = bytes.fromhex(tail_hex)
        # Reverse to get the encoded string
        decoded = tail_bytes.decode("ascii")
        assert "".join(reversed(decoded)) == "TURBOHMI2017"


# ======================================================================
# Field definitions
# ======================================================================


class TestFieldDefs:
    def test_all_battery_channels_registered(self):
        for ch in BatteryChannel:
            assert get_field_def(Sender.BATTERY, ch) is not None, (
                f"Missing: BATTERY/{ch.name}"
            )

    def test_all_motor_channels_registered(self):
        for ch in MotorChannel:
            assert get_field_def(Sender.MOTOR, ch) is not None, (
                f"Missing: MOTOR/{ch.name}"
            )

    def test_all_settings_channels_registered(self):
        for ch in BikeSettingsChannel:
            assert get_field_def(Sender.BIKE_SETTINGS, ch) is not None, (
                f"Missing: SETTINGS/{ch.name}"
            )

    def test_secondary_battery_channels_registered(self):
        for ch in BatteryChannel:
            assert get_field_def(Sender.BATTERY_2, ch) is not None, (
                f"Missing: BATTERY_2/{ch.name}"
            )

    def test_field_def_returns_none_for_unknown(self):
        assert get_field_def(0xFF, 0xFF) is None

    def test_all_field_defs_count(self):
        defs = all_field_defs()
        # 8 battery + 9 motor + 6 settings + 8 battery2 = 31
        assert len(defs) == 31


# ======================================================================
# Message parsing — battery (sender 0x00)
# ======================================================================


class TestParseBattery:
    def test_battery_capacity_wh(self):
        # Example from reference: 00 00 c2 01 → raw=0x01c2=450 → 450*1.1111≈500 Wh
        msg = parse_message(bytes.fromhex("0000c201"))
        assert msg.sender == 0x00
        assert msg.channel == 0x00
        assert msg.raw_value == 0x01C2  # 450
        assert msg.converted_value == 500
        assert msg.field_name == "battery_capacity_wh"
        assert msg.unit == "Wh"

    def test_battery_remaining_wh(self):
        # 00 01 e4 00 → raw=0x00e4=228 → 228*1.1111≈253 Wh
        msg = parse_message(bytes.fromhex("0001e400"))
        assert msg.sender == 0x00
        assert msg.channel == 0x01
        assert msg.raw_value == 228
        assert msg.converted_value == 253
        assert msg.field_name == "battery_remaining_wh"

    def test_battery_health(self):
        # 00 02 64 → raw=100 → 100%
        msg = parse_message(bytes.fromhex("000264"))
        assert msg.converted_value == 100
        assert msg.field_name == "battery_health"
        assert msg.unit == "%"

    def test_battery_temp(self):
        # 00 03 13 → raw=19 → 19°C
        msg = parse_message(bytes.fromhex("000313"))
        assert msg.converted_value == 19
        assert msg.field_name == "battery_temp"
        assert msg.unit == "°C"

    def test_battery_charge_cycles(self):
        # 00 04 0d 00 → raw=13 → 13 cycles
        msg = parse_message(bytes.fromhex("00040d00"))
        assert msg.converted_value == 13
        assert msg.field_name == "battery_charge_cycles"

    def test_battery_voltage(self):
        # 00 05 50 → raw=80 → 80/5+20=36.0 V
        msg = parse_message(bytes.fromhex("000550"))
        assert msg.converted_value == pytest.approx(36.0)
        assert msg.field_name == "battery_voltage"
        assert msg.unit == "V"

    def test_battery_current(self):
        # 00 06 00 → raw=0 → 0/5=0.0 A
        msg = parse_message(bytes.fromhex("000600"))
        assert msg.converted_value == pytest.approx(0.0)
        assert msg.field_name == "battery_current"

    def test_battery_charge_percent(self):
        # 00 0c 34 → raw=52 → 52%
        msg = parse_message(bytes.fromhex("000c34"))
        assert msg.converted_value == 52
        assert msg.field_name == "battery_charge_percent"


# ======================================================================
# Message parsing — motor/rider (sender 0x01)
# ======================================================================


class TestParseMotor:
    def test_rider_power(self):
        # 01 00 00 00 → raw=0 → 0 W
        msg = parse_message(bytes.fromhex("01000000"))
        assert msg.converted_value == 0
        assert msg.field_name == "rider_power"
        assert msg.unit == "W"

    def test_rider_power_nonzero(self):
        # 01 00 c8 00 → raw=200 → 200 W
        msg = parse_message(bytes.fromhex("0100c800"))
        assert msg.converted_value == 200

    def test_cadence(self):
        # 01 01 33 00 → raw=51 → 51/10=5.1 RPM
        msg = parse_message(bytes.fromhex("01013300"))
        assert msg.converted_value == pytest.approx(5.1)
        assert msg.field_name == "cadence"

    def test_cadence_normal(self):
        # 01 01 2c 03 → raw=812 → 81.2 RPM
        msg = parse_message(bytes.fromhex("01012c03"))
        assert msg.converted_value == pytest.approx(81.2)

    def test_speed(self):
        # 01 02 61 00 → raw=97 → 97/10=9.7 km/h
        msg = parse_message(bytes.fromhex("01026100"))
        assert msg.converted_value == pytest.approx(9.7)
        assert msg.field_name == "speed"
        assert msg.unit == "km/h"

    def test_speed_25kmh(self):
        # 01 02 fa 00 → raw=250 → 25.0 km/h
        msg = parse_message(bytes.fromhex("0102fa00"))
        assert msg.converted_value == pytest.approx(25.0)

    def test_odometer(self):
        # 01 04 9e d1 39 00 → raw=0x0039d19e=3789214 → 3789.214 km
        msg = parse_message(bytes.fromhex("01049ed13900"))
        assert msg.raw_value == 3789214
        assert msg.converted_value == pytest.approx(3789.214)
        assert msg.field_name == "odometer"

    def test_assist_level_off(self):
        msg = parse_message(bytes.fromhex("01050000"))
        assert msg.converted_value == AssistLevel.OFF

    def test_assist_level_eco(self):
        msg = parse_message(bytes.fromhex("01050100"))
        assert msg.converted_value == AssistLevel.ECO

    def test_assist_level_trail(self):
        # 01 05 02 00 → assist=2 → TRAIL
        msg = parse_message(bytes.fromhex("01050200"))
        assert msg.converted_value == AssistLevel.TRAIL

    def test_assist_level_turbo(self):
        msg = parse_message(bytes.fromhex("01050300"))
        assert msg.converted_value == AssistLevel.TURBO

    def test_motor_temp(self):
        # 01 07 19 → raw=25 → 25°C
        msg = parse_message(bytes.fromhex("010719"))
        assert msg.converted_value == 25
        assert msg.field_name == "motor_temp"

    def test_motor_power(self):
        # 01 0c 02 00 → raw=2 → 2 W
        msg = parse_message(bytes.fromhex("010c0200"))
        assert msg.converted_value == 2
        assert msg.field_name == "motor_power"

    def test_shuttle(self):
        # 01 15 00 → shuttle=0
        msg = parse_message(bytes.fromhex("011500"))
        assert msg.converted_value == 0
        assert msg.field_name == "shuttle"


# ======================================================================
# Message parsing — bike settings (sender 0x02)
# ======================================================================


class TestParseSettings:
    def test_wheel_circumference(self):
        # 02 00 fc 08 → raw=0x08fc=2300 → 2300 mm
        msg = parse_message(bytes.fromhex("0200fc08"))
        assert msg.converted_value == 2300
        assert msg.field_name == "wheel_circumference"
        assert msg.unit == "mm"

    def test_assist_lev1(self):
        # 02 03 0a → raw=10 → 10%
        msg = parse_message(bytes.fromhex("02030a"))
        assert msg.converted_value == 10
        assert msg.field_name == "assist_lev1_pct"

    def test_assist_lev2(self):
        # 02 04 14 → raw=20 → 20%
        msg = parse_message(bytes.fromhex("020414"))
        assert msg.converted_value == 20
        assert msg.field_name == "assist_lev2_pct"

    def test_assist_lev3(self):
        # 02 05 32 → raw=50 → 50%
        msg = parse_message(bytes.fromhex("020532"))
        assert msg.converted_value == 50
        assert msg.field_name == "assist_lev3_pct"

    def test_acceleration(self):
        # 02 07 a0 0f → raw=0x0fa0=4000 → (4000-3000)/60 ≈ 16.67%
        msg = parse_message(bytes.fromhex("0207a00f"))
        assert msg.converted_value == pytest.approx(16.6667, rel=1e-3)
        assert msg.field_name == "acceleration"


# ======================================================================
# Message parsing — secondary battery (sender 0x04)
# ======================================================================


class TestParseSecondaryBattery:
    def test_battery2_charge_percent(self):
        msg = parse_message(bytes.fromhex("040c50"))
        assert msg.converted_value == 80
        assert msg.field_name == "battery2_charge_percent"


# ======================================================================
# Edge cases
# ======================================================================


class TestEdgeCases:
    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            parse_message(b"\x00\x01")

    def test_minimum_3_bytes(self):
        # 3 bytes is valid (sender + channel + 1 byte data)
        msg = parse_message(bytes.fromhex("000264"))
        assert msg.field_name == "battery_health"

    def test_unknown_sender(self):
        msg = parse_message(bytes.fromhex("FF0042"))
        assert msg.field_name is None
        assert msg.raw_value == 0x42

    def test_unknown_channel(self):
        msg = parse_message(bytes.fromhex("00FF42"))
        assert msg.field_name is None

    def test_extra_trailing_bytes_ignored(self):
        """Parser should use the defined data_size and ignore extra bytes."""
        # battery_health is 1 byte, but we send 3 extra
        msg = parse_message(bytes.fromhex("000264AABBCC"))
        assert msg.converted_value == 100  # only reads 1 byte


# ======================================================================
# Advertising detection
# ======================================================================


class TestAdvertising:
    def test_detects_specialized_advert(self):
        # Full manufacturer data payload (company ID already stripped by bleak)
        payload = bytes.fromhex("545552424f484d493230313701000000")
        assert is_specialized_advertisement({NORDIC_COMPANY_ID: payload}) is True

    def test_rejects_non_nordic(self):
        payload = bytes.fromhex("545552424f484d493230313701000000")
        assert is_specialized_advertisement({0x1234: payload}) is False

    def test_rejects_wrong_payload(self):
        assert is_specialized_advertisement({NORDIC_COMPANY_ID: b"NOT_A_BIKE"}) is False

    def test_rejects_empty(self):
        assert is_specialized_advertisement({}) is False


# ======================================================================
# Request builder
# ======================================================================


class TestBuildRequest:
    def test_basic_request(self):
        assert build_request(0x00, 0x0C) == b"\x00\x0c"

    def test_motor_speed_request(self):
        assert build_request(Sender.MOTOR, MotorChannel.SPEED) == b"\x01\x02"


# ======================================================================
# Gen 1 UUID generation
# ======================================================================


class TestGen1UUIDs:
    def test_gen1_uuid_base_format(self):
        uuid = _uuid_gen1(0x0013)
        assert uuid == "00000013-0000-4b49-4e4f-525441474947"

    def test_gen1_service_notify_uuid(self):
        assert SERVICE_DATA_NOTIFY_GEN1 == "00000003-0000-4b49-4e4f-525441474947"

    def test_gen1_service_request_uuid(self):
        assert SERVICE_DATA_REQUEST_GEN1 == "00000001-0000-4b49-4e4f-525441474947"

    def test_gen1_service_write_uuid(self):
        assert SERVICE_DATA_WRITE_GEN1 == "00000002-0000-4b49-4e4f-525441474947"

    def test_gen1_char_notify_uuid(self):
        assert CHAR_NOTIFY_GEN1 == "00000013-0000-4b49-4e4f-525441474947"

    def test_gen1_char_request_write_uuid(self):
        assert CHAR_REQUEST_WRITE_GEN1 == "00000021-0000-4b49-4e4f-525441474947"

    def test_gen1_char_request_read_uuid(self):
        assert CHAR_REQUEST_READ_GEN1 == "00000011-0000-4b49-4e4f-525441474947"

    def test_gen1_char_write_uuid(self):
        assert CHAR_WRITE_GEN1 == "00000012-0000-4b49-4e4f-525441474947"

    def test_gen1_uuid_base_contains_gigatronik(self):
        """Last 10 bytes of Gen 1 UUID base decode to GIGATRONIK reversed."""
        uuid = _uuid_gen1(0x0000)
        # Extract: 0000-4b49-4e4f-525441474947
        parts = uuid.split("-")
        tail_hex = "".join(parts[2:])  # 4b494e4f525441474947
        tail_bytes = bytes.fromhex(tail_hex)
        decoded = tail_bytes.decode("ascii")
        assert "".join(reversed(decoded)) == "GIGATRONIK"

    def test_get_uuid_gen1(self):
        assert get_uuid(ProtocolGeneration.GEN_1, 0x0013) == CHAR_NOTIFY_GEN1

    def test_get_uuid_gen2(self):
        assert get_uuid(ProtocolGeneration.GEN_2, 0x0013) == CHAR_NOTIFY

    def test_get_char_notify_gen1(self):
        assert get_char_notify(ProtocolGeneration.GEN_1) == CHAR_NOTIFY_GEN1

    def test_get_char_notify_gen2(self):
        assert get_char_notify(ProtocolGeneration.GEN_2) == CHAR_NOTIFY


# ======================================================================
# Gen 1 advertising detection
# ======================================================================


class TestGen1Advertising:
    def test_detects_gen1_simplo(self):
        """Gen 1 bikes advertise with Simplo Technology manufacturer ID."""
        payload = bytes.fromhex("028657" + "ff" * 24)
        assert is_specialized_advertisement({SIMPLO_COMPANY_ID: payload}) is True

    def test_detect_generation_gen1(self):
        payload = bytes.fromhex("028657" + "ff" * 24)
        assert detect_generation({SIMPLO_COMPANY_ID: payload}) == ProtocolGeneration.GEN_1

    def test_detect_generation_gen2(self):
        payload = bytes.fromhex("545552424f484d493230313701000000")
        assert detect_generation({NORDIC_COMPANY_ID: payload}) == ProtocolGeneration.GEN_2

    def test_detect_generation_unknown(self):
        assert detect_generation({}) is None
        assert detect_generation({0x1234: b"random"}) is None

    def test_gen1_with_serial_number_payload(self):
        """Real Gen 1 manufacturer data from a 2018 Turbo Levo."""
        payload = bytes.fromhex(
            "02865701433937323732"
            "2D313033303331373330333830382D322D30303538"
        )
        assert detect_generation({SIMPLO_COMPANY_ID: payload}) == ProtocolGeneration.GEN_1


# ======================================================================
# Gen 1 message parsing (same format as Gen 2)
# ======================================================================


class TestGen1MessageParsing:
    def test_gen1_notification_with_ff_padding(self):
        """Gen 1 sends 20-byte notifications padded with 0xFF."""
        # 01 05 01 00 FF FF... → assist_level ECO, padded with FF
        data = bytes.fromhex("01050100" + "ff" * 16)
        msg = parse_message(data)
        assert msg.field_name == "assist_level"
        assert msg.converted_value == AssistLevel.ECO

    def test_gen1_battery_charge_with_padding(self):
        """Gen 1 battery charge notification with FF padding."""
        # 00 0c 34 FF FF... → battery_charge_percent = 52%
        data = bytes.fromhex("000c34" + "ff" * 17)
        msg = parse_message(data)
        assert msg.field_name == "battery_charge_percent"
        assert msg.converted_value == 52
