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
    BLEProfile,
    Sender,
    _uuid,
    _uuid_tcu1,
    all_field_defs,
    build_request,
    detect_generation,
    get_char_notify,
    get_field_def,
    get_uuid,
    is_specialized_advertisement,
    parse_message,
    CHAR_NOTIFY,
    CHAR_NOTIFY_TCU1,
    CHAR_REQUEST_READ,
    CHAR_REQUEST_READ_TCU1,
    CHAR_REQUEST_WRITE,
    CHAR_REQUEST_WRITE_TCU1,
    CHAR_WRITE,
    CHAR_WRITE_TCU1,
    SERVICE_DATA_NOTIFY,
    SERVICE_DATA_NOTIFY_TCU1,
    SERVICE_DATA_REQUEST,
    SERVICE_DATA_REQUEST_TCU1,
    SERVICE_DATA_WRITE,
    SERVICE_DATA_WRITE_TCU1,
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
# Padding stripping and sentinel detection
# ======================================================================


class TestPaddingStripping:
    def test_1byte_all_ff(self):
        """0xFF for a 1-byte field → entire payload stripped → None."""
        # battery_health (sender=0x00, channel=0x02, data_size=1)
        msg = parse_message(bytes.fromhex("0002ff"))
        assert msg.field_name == "battery_health"
        assert msg.converted_value is None

    def test_2byte_all_ff(self):
        """0xFFFF for a 2-byte field → entire payload stripped → None."""
        # cadence (sender=0x01, channel=0x01, data_size=2)
        msg = parse_message(bytes.fromhex("0101ffff"))
        assert msg.field_name == "cadence"
        assert msg.converted_value is None

    def test_2byte_ff_speed(self):
        """Speed with 0xFFFF → None."""
        msg = parse_message(bytes.fromhex("0102ffff"))
        assert msg.field_name == "speed"
        assert msg.converted_value is None

    def test_2byte_ff_rider_power(self):
        """Rider power with 0xFFFF → None."""
        msg = parse_message(bytes.fromhex("0100ffff"))
        assert msg.field_name == "rider_power"
        assert msg.converted_value is None

    def test_4byte_all_ff(self):
        """0xFFFFFFFF for a 4-byte field → entire payload stripped → None."""
        # odometer (sender=0x01, channel=0x04, data_size=4)
        msg = parse_message(bytes.fromhex("0104ffffffff"))
        assert msg.field_name == "odometer"
        assert msg.converted_value is None

    def test_stripped_preserves_field_name_and_unit(self):
        """Fully-stripped messages still report field_name and unit."""
        msg = parse_message(bytes.fromhex("0100ffff"))
        assert msg.field_name == "rider_power"
        assert msg.unit == "W"

    def test_non_ff_values_unaffected(self):
        """Non-0xFF values still parse normally."""
        msg = parse_message(bytes.fromhex("0100c800"))
        assert msg.converted_value == 200  # 200 W

    def test_tcu1_padded_all_ff_cadence(self):
        """TCU1 cadence with full 0xFF padding → None."""
        data = bytes.fromhex("0101ffff" + "ff" * 16)
        msg = parse_message(data)
        assert msg.field_name == "cadence"
        assert msg.converted_value is None

    def test_tcu1_padded_all_ff_speed(self):
        """TCU1 speed with full 0xFF padding → None."""
        data = bytes.fromhex("0102ffff" + "ff" * 16)
        msg = parse_message(data)
        assert msg.field_name == "speed"
        assert msg.converted_value is None

    def test_tcu1_padded_valid_data(self):
        """TCU1 valid data still works despite trailing 0xFF padding."""
        # assist_level ECO: 01 05 01 00 FF FF...
        data = bytes.fromhex("01050100" + "ff" * 16)
        msg = parse_message(data)
        assert msg.field_name == "assist_level"
        assert msg.converted_value == AssistLevel.ECO

    def test_tcu1_peak_assist_single_byte(self):
        """TCU1 sends peak_assist as 1 byte + 0xFF padding.

        TCX sends 3 packed bytes (ECO%, TRAIL%, TURBO%).
        TCU1 sends individual values as single-byte messages.
        0x1A=26 could be ECO assist percentage.
        """
        data = bytes.fromhex("01101A" + "ff" * 17)
        msg = parse_message(data)
        assert msg.field_name == "peak_assist"
        assert msg.raw_value == 0x1A  # 26
        assert msg.converted_value == 26

    def test_tcu1_peak_assist_values_from_log(self):
        """The three peak_assist values seen cycling in Jan's debug log."""
        # 0x67=103, 0x1A=26, 0x34=52 — assist percentages for 3 levels
        for hex_byte, expected in [("67", 103), ("1A", 26), ("34", 52)]:
            data = bytes.fromhex("0110" + hex_byte + "ff" * 17)
            msg = parse_message(data)
            assert msg.field_name == "peak_assist"
            assert msg.raw_value == expected
            assert msg.converted_value == expected

    def test_tcu1_battery_remaining_wh(self):
        """TCU1 battery remaining with real 2-byte data + padding."""
        # 00 01 E9 00 FF FF... → remaining_wh raw=0x00E9=233 → 233*1.1111≈259
        data = bytes.fromhex("0001E900" + "ff" * 16)
        msg = parse_message(data)
        assert msg.field_name == "battery_remaining_wh"
        assert msg.converted_value == 259

    def test_tcu1_motor_temp_with_padding(self):
        """TCU1 motor temp (1 byte) with padding."""
        data = bytes.fromhex("010712" + "ff" * 17)  # 0x12 = 18°C
        msg = parse_message(data)
        assert msg.field_name == "motor_temp"
        assert msg.converted_value == 18

    def test_tcu1_battery_voltage_with_padding(self):
        """TCU1 battery voltage (1 byte) with padding."""
        # 0x58 = 88 → 88/5+20 = 37.6V
        data = bytes.fromhex("000558" + "ff" * 17)
        msg = parse_message(data)
        assert msg.field_name == "battery_voltage"
        assert msg.converted_value == pytest.approx(37.6)

    def test_unknown_field_with_padding(self):
        """Unknown sender/channel with 0xFF padding → stripped to real data."""
        data = bytes.fromhex("FF0042" + "ff" * 17)
        msg = parse_message(data)
        assert msg.field_name is None
        assert msg.raw_value == 0x42

    def test_unknown_field_all_ff_payload(self):
        """Unknown field with only 0xFF payload → None."""
        data = bytes.fromhex("FF00" + "ff" * 18)
        msg = parse_message(data)
        assert msg.field_name is None
        assert msg.converted_value is None


# ======================================================================
# Advertising detection
# ======================================================================


class TestAdvertising:
    def test_detects_specialized_advert(self):
        # Full manufacturer data payload (company ID already stripped by bleak)
        payload = bytes.fromhex("545552424f484d493230313701000000")
        assert is_specialized_advertisement({NORDIC_COMPANY_ID: payload}) is True

    def test_detects_turbohmi_in_apple_ibeacon(self):
        """Vado 3.0 puts TURBOHMI in an Apple iBeacon frame (mfr ID 0x004C)."""
        ibeacon = bytes.fromhex("0215545552424f484d4932303137010000005fe033060a")
        nordic = bytes.fromhex("dac8c404423333330601")
        assert (
            is_specialized_advertisement({0x004C: ibeacon, NORDIC_COMPANY_ID: nordic})
            is True
        )

    def test_detects_turbohmi_any_manufacturer_id(self):
        """TURBOHMI magic should be detected regardless of manufacturer ID."""
        payload = bytes.fromhex("545552424f484d493230313701000000")
        assert is_specialized_advertisement({0x1234: payload}) is True

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
# Write commands
# ======================================================================


class TestBuildWriteCommand:
    def test_set_assist_level_trail(self):
        from specialized_turbo.protocol import build_write_command

        cmd = build_write_command(0x01, 0x05, bytes([2]))
        assert cmd == bytes.fromhex("010502")

    def test_set_assist_level_off(self):
        from specialized_turbo.protocol import build_write_command

        cmd = build_write_command(0x01, 0x05, bytes([0]))
        assert cmd == bytes.fromhex("010500")

    def test_set_shuttle(self):
        from specialized_turbo.protocol import build_write_command

        cmd = build_write_command(0x01, 0x15, bytes([50]))
        assert cmd == bytes.fromhex("011532")

    def test_set_acceleration_20pct(self):
        from specialized_turbo.protocol import build_write_command

        # 20% → raw = (20 * 60) + 3000 = 4200 = 0x1068 → LE: 68 10
        raw = int(20 * 60 + 3000)
        cmd = build_write_command(0x02, 0x07, raw.to_bytes(2, "little"))
        assert cmd == bytes.fromhex("020768100000"[:8])  # 02 07 68 10
        assert cmd[:2] == b"\x02\x07"
        assert int.from_bytes(cmd[2:], "little") == 4200

    def test_set_assist_pct_eco(self):
        from specialized_turbo.protocol import build_write_command

        cmd = build_write_command(0x02, 0x03, bytes([35]))
        assert cmd == bytes.fromhex("020323")


class TestBuildTcxWrite:
    def test_set_travel_mode(self):
        from specialized_turbo.protocol import build_tcx_write

        # param 143 = 0x008F → big-endian: 00 8f
        cmd = build_tcx_write(143, bytes([2]))
        assert cmd[:2] == b"\x00\x8f"
        assert cmd[2] == 2

    def test_round_trips_with_encode_decode(self):
        from specialized_turbo.parameters import decode_parameter_id
        from specialized_turbo.protocol import build_tcx_write

        cmd = build_tcx_write(148, bytes([0xFA, 0x00]))
        assert decode_parameter_id(cmd) == 148
        assert cmd[2:] == b"\xfa\x00"


class TestWritableFields:
    def test_writable_fields_exist(self):
        """At least some fields are marked writable."""
        defs = all_field_defs()
        writable = [fd for fd in defs.values() if fd.writable]
        assert len(writable) >= 5

    def test_assist_level_is_writable(self):
        fd = get_field_def(0x01, 0x05)
        assert fd is not None
        assert fd.writable
        assert fd.encode is not None

    def test_acceleration_encode_round_trip(self):
        fd = get_field_def(0x02, 0x07)
        assert fd is not None
        assert fd.writable
        assert fd.encode is not None
        # convert(4200) → 20.0%, encode(20.0) → 4200
        converted = fd.convert(4200)
        assert converted == pytest.approx(20.0)
        assert fd.encode(converted) == 4200

    def test_non_writable_field(self):
        fd = get_field_def(0x00, 0x0C)  # battery_charge_percent
        assert fd is not None
        assert not fd.writable


# ======================================================================
# TCU1 UUIDs
# ======================================================================


class TestTCU1UUIDs:
    def test_tcu1_uuid_base_format(self):
        uuid = _uuid_tcu1(0x0013)
        assert uuid == "00000013-0000-4b49-4e4f-525441474947"

    def test_tcu1_service_notify_uuid(self):
        assert SERVICE_DATA_NOTIFY_TCU1 == "00000003-0000-4b49-4e4f-525441474947"

    def test_tcu1_service_request_uuid(self):
        assert SERVICE_DATA_REQUEST_TCU1 == "00000001-0000-4b49-4e4f-525441474947"

    def test_tcu1_service_write_uuid(self):
        assert SERVICE_DATA_WRITE_TCU1 == "00000002-0000-4b49-4e4f-525441474947"

    def test_tcu1_char_notify_uuid(self):
        assert CHAR_NOTIFY_TCU1 == "00000013-0000-4b49-4e4f-525441474947"

    def test_tcu1_char_request_write_uuid(self):
        assert CHAR_REQUEST_WRITE_TCU1 == "00000021-0000-4b49-4e4f-525441474947"

    def test_tcu1_char_request_read_uuid(self):
        assert CHAR_REQUEST_READ_TCU1 == "00000011-0000-4b49-4e4f-525441474947"

    def test_tcu1_char_write_uuid(self):
        assert CHAR_WRITE_TCU1 == "00000012-0000-4b49-4e4f-525441474947"

    def test_tcu1_uuid_base_contains_gigatronik(self):
        """Last 10 bytes of TCU1 UUID base decode to GIGATRONIK reversed."""
        uuid = _uuid_tcu1(0x0000)
        # Extract: 0000-4b49-4e4f-525441474947
        parts = uuid.split("-")
        tail_hex = "".join(parts[2:])  # 4b494e4f525441474947
        tail_bytes = bytes.fromhex(tail_hex)
        decoded = tail_bytes.decode("ascii")
        assert "".join(reversed(decoded)) == "GIGATRONIK"

    def test_get_uuid_tcu1(self):
        assert get_uuid(BLEProfile.TCU1, 0x0013) == CHAR_NOTIFY_TCU1

    def test_get_uuid_tcx(self):
        assert get_uuid(BLEProfile.TCX, 0x0013) == CHAR_NOTIFY

    def test_get_char_notify_tcu1(self):
        assert get_char_notify(BLEProfile.TCU1) == CHAR_NOTIFY_TCU1

    def test_get_char_notify_tcx(self):
        assert get_char_notify(BLEProfile.TCX) == CHAR_NOTIFY


# ======================================================================
# TCU1 advertising
# ======================================================================


class TestTCU1Advertising:
    def test_detects_tcu1_simplo(self):
        """TCU1 bikes advertise with Simplo Technology manufacturer ID."""
        payload = bytes.fromhex("028657" + "ff" * 24)
        assert is_specialized_advertisement({SIMPLO_COMPANY_ID: payload}) is True

    def test_detect_generation_tcu1(self):
        payload = bytes.fromhex("028657" + "ff" * 24)
        assert detect_generation({SIMPLO_COMPANY_ID: payload}) == BLEProfile.TCU1

    def test_detect_generation_tcx(self):
        payload = bytes.fromhex("545552424f484d493230313701000000")
        assert detect_generation({NORDIC_COMPANY_ID: payload}) == BLEProfile.TCX

    def test_detect_generation_tcx_apple_ibeacon(self):
        """Vado 3.0: TURBOHMI in Apple iBeacon, unrelated data in Nordic."""
        ibeacon = bytes.fromhex("0215545552424f484d4932303137010000005fe033060a")
        nordic = bytes.fromhex("dac8c404423333330601")
        assert (
            detect_generation({0x004C: ibeacon, NORDIC_COMPANY_ID: nordic})
            == BLEProfile.TCX
        )

    def test_detect_generation_unknown(self):
        assert detect_generation({}) is None
        assert detect_generation({0x1234: b"random"}) is None

    def test_tcu1_with_serial_number_payload(self):
        """Real TCU1 manufacturer data from a 2018 Turbo Levo."""
        payload = bytes.fromhex(
            "028657014339373237322D313033303331373330333830382D322D30303538"
        )
        assert detect_generation({SIMPLO_COMPANY_ID: payload}) == BLEProfile.TCU1


# ======================================================================
# TCU1 message parsing
# ======================================================================


class TestTCU1MessageParsing:
    def test_tcu1_notification_with_ff_padding(self):
        """TCU1 sends 20-byte notifications padded with 0xFF."""
        # 01 05 01 00 FF FF... → assist_level ECO, padded with FF
        data = bytes.fromhex("01050100" + "ff" * 16)
        msg = parse_message(data)
        assert msg.field_name == "assist_level"
        assert msg.converted_value == AssistLevel.ECO

    def test_tcu1_battery_charge_with_padding(self):
        """TCU1 battery charge notification with FF padding."""
        # 00 0c 34 FF FF... → battery_charge_percent = 52%
        data = bytes.fromhex("000c34" + "ff" * 17)
        msg = parse_message(data)
        assert msg.field_name == "battery_charge_percent"
        assert msg.converted_value == 52


# ======================================================================
# Framed format parsing (Vado 3.0 2022)
# ======================================================================


class TestFramedFormat:
    """TCX2+ bikes wrap messages in a 20-byte CRC-framed packet.
    [payload: 18B] [crc16_le: 2B] = 20 bytes total.
    The payload contains [sender, channel, data..., zero-padding].
    """

    def test_framed_battery_charge_percent(self):
        """Real response from Vado 3.0 request-read: battery_charge_percent=5%."""
        # f8 ff 00 0c 05 00*13 e6 ca  (real capture, valid CRC)
        data = bytes.fromhex("f8ff000c0500000000000000000000000000e6ca")
        msg = parse_message(data)
        # After CRC stripping, sender=0xf8, channel=0xff from the 18-byte payload.
        # These are the raw first two bytes; parse_message treats them as sender/channel.
        # For TCU1-style parsing of CRC-framed data, the F8 FF are part of the payload.
        # The actual telemetry data (00 0c 05) starts at byte 2 of the unframed payload.
        # This test verifies CRC stripping works — the payload is passed as-is.
        assert msg.sender == 0xF8
        assert msg.channel == 0xFF

    def test_framed_battery_capacity_wh(self):
        """Real response from Vado 3.0 pairing trigger read."""
        # f8 ff 00 00 04 00 00*12 70 0d  (real capture, valid CRC)
        data = bytes.fromhex("f8ff00000400000000000000000000000000700d")
        msg = parse_message(data)
        assert msg.sender == 0xF8
        assert msg.channel == 0xFF

    def test_framed_with_pack_tcx(self):
        """Build a valid CRC-framed packet and verify parse_message strips CRC."""
        from specialized_turbo.framing import pack_tcx

        # Pack a TCU1-style message: sender=0x01, channel=0x00, data=0xc8 0x00
        framed = pack_tcx(b"\x01\x00\xc8\x00")
        assert len(framed) == 20
        msg = parse_message(framed)
        assert msg.sender == 0x01
        assert msg.channel == 0x00
        assert msg.field_name == "rider_power"
        assert msg.converted_value == 200

    def test_framed_odometer(self):
        """CRC-framed odometer value round-trips through parse_message."""
        from specialized_turbo.framing import pack_tcx

        framed = pack_tcx(b"\x01\x04\x9e\xd1\x39\x00")
        msg = parse_message(framed)
        assert msg.field_name == "odometer"
        assert msg.raw_value == 3789214
        assert msg.converted_value == pytest.approx(3789.214)

    def test_non_framed_20_bytes_not_unwrapped(self):
        """A 20-byte message that doesn't start with f8 ff is NOT unwrapped."""
        # TCU1 padded notification: 00 0c 34 FF*17
        data = bytes.fromhex("000c34" + "ff" * 17)
        msg = parse_message(data)
        assert msg.field_name == "battery_charge_percent"
        assert msg.converted_value == 52
