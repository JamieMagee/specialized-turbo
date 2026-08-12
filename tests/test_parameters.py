"""
Unit tests for parameters.py — BikeParameter enum and TCX field definitions.
"""

import pytest

from specialized_turbo.parameters import (
    BikeParameter,
    all_tcx_fields,
    decode_parameter_id,
    encode_parameter_id,
    get_tcx_field,
)


class TestBikeParameterEnum:
    def test_battery1_soc(self):
        assert BikeParameter.BATTERY1_STATE_OF_CHARGE == 26

    def test_motor_speed(self):
        assert BikeParameter.MOTOR_BIKE_SPEED == 149

    def test_system_state(self):
        assert BikeParameter.SYSTEM_STATE == 364

    def test_get_new_vi(self):
        """Special identification parameter."""
        assert BikeParameter.SYSTEM_GET_NEW_VI == 301

    def test_total_members(self):
        """Regression guard for the app enum plus two native-only parameters."""
        assert len(BikeParameter) == 353


class TestEncodeDecodeParameterId:
    def test_encode_battery_soc(self):
        # BikeParameter 26 = 0x001A → big-endian bytes: 00 1a
        result = encode_parameter_id(26)
        assert result == b"\x00\x1a"

    def test_encode_system_state(self):
        # BikeParameter 364 = 0x016C → big-endian: 01 6c
        result = encode_parameter_id(364)
        assert result == b"\x01\x6c"

    def test_decode_round_trip(self):
        for param_id in [0, 1, 26, 148, 300, 363, 414]:
            encoded = encode_parameter_id(param_id)
            decoded = decode_parameter_id(encoded)
            assert decoded == param_id

    def test_decode_big_endian(self):
        assert decode_parameter_id(b"\x01\x6b") == 363


class TestTCXFieldDefinitions:
    def test_battery_charge_percent(self):
        fd = get_tcx_field(BikeParameter.BATTERY1_STATE_OF_CHARGE)
        assert fd is not None
        assert fd.name == "battery_charge_percent"
        assert fd.unit == "%"
        assert fd.data_size == 1
        assert fd.convert(52) == 52

    def test_speed_conversion(self):
        fd = get_tcx_field(BikeParameter.MOTOR_BIKE_SPEED)
        assert fd is not None
        assert fd.name == "speed"
        assert fd.convert(250) == pytest.approx(25.0)

    def test_cadence_conversion(self):
        fd = get_tcx_field(BikeParameter.MOTOR_BIKE_CADENCE)
        assert fd is not None
        assert fd.convert(812) == pytest.approx(81.2)

    def test_odometer_conversion(self):
        fd = get_tcx_field(BikeParameter.MOTOR_ODOMETER)
        assert fd is not None
        assert fd.convert(3789214) == pytest.approx(3789.214)

    def test_unknown_param_returns_none(self):
        assert get_tcx_field(9999) is None

    def test_all_tcx_fields_count(self):
        fields = all_tcx_fields()
        # At least the core telemetry fields we registered
        assert len(fields) >= 30

    def test_battery2_mirrors_battery1(self):
        fd1 = get_tcx_field(BikeParameter.BATTERY1_STATE_OF_CHARGE)
        fd2 = get_tcx_field(BikeParameter.BATTERY2_STATE_OF_CHARGE)
        assert fd1 is not None and fd2 is not None
        assert fd1.unit == fd2.unit


class TestTCXWritableFields:
    def test_assist_level_writable(self):
        fd = get_tcx_field(BikeParameter.MOTOR_ACTIVE_TRAVEL_MODE)
        assert fd is not None
        assert fd.writable
        assert fd.encode is not None
        assert fd.encode(2) == 2

    def test_acceleration_encode_round_trip(self):
        fd = get_tcx_field(BikeParameter.MOTOR_ACCELERATION_RESPONSE)
        assert fd is not None
        assert fd.writable
        converted = fd.convert(4200)
        assert converted == pytest.approx(20.0)
        assert fd.encode is not None
        assert fd.encode(converted) == 4200

    def test_max_speed_encode_round_trip(self):
        fd = get_tcx_field(BikeParameter.MOTOR_MAX_SPEED_LIMIT)
        assert fd is not None
        assert fd.writable
        assert fd.encode is not None
        converted = fd.convert(250)
        assert converted == pytest.approx(25.0)
        assert fd.encode(converted) == 250

    def test_wheel_size_writable(self):
        fd = get_tcx_field(BikeParameter.MOTOR_WHEEL_SIZE)
        assert fd is not None
        assert fd.writable

    def test_read_only_field_not_writable(self):
        fd = get_tcx_field(BikeParameter.BATTERY1_STATE_OF_CHARGE)
        assert fd is not None
        assert not fd.writable
