"""
BikeParameter definitions for Specialized Turbo TCX2/TCX3/TCX4 protocols.

The TCX2+ protocol addresses telemetry fields by a flat 16-bit parameter ID
(sent big-endian on the wire) instead of the TCU1 sender/channel pairs.

Parameter IDs and names were extracted from the Specialized Mission Control
Android app (``com.specialized.turboconnect.model.BikeParameter``).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from collections.abc import Callable


# ---------------------------------------------------------------------------
# BikeParameter enum — all 352 known parameter IDs
# ---------------------------------------------------------------------------


class BikeParameter(IntEnum):
    """Parameter IDs used on the TCX2/TCX3/TCX4 wire protocol."""

    # Battery 1
    BATTERY1_CHARGING_ACTIVE = 0
    BATTERY1_CURRENT_LEVEL = 1
    BATTERY1_DFU_CELL = 2
    BATTERY1_DFU_FW = 3
    BATTERY1_DFU_HW = 4
    BATTERY1_DFU_MCUTYPE = 5
    BATTERY1_DFU_PROJECT = 6
    BATTERY1_DFU_SAFETYSTATUS = 7
    BATTERY1_ERROR_CODES = 8
    BATTERY1_ERROR_CODES_2 = 10
    BATTERY1_FAULT_LOG_ENTRIES = 13
    BATTERY1_FIRMWARE = 14
    BATTERY1_FULL_CAPACITY = 15
    BATTERY1_HARDWARE = 16
    BATTERY1_HEALTH = 17
    BATTERY1_MAX_UNCHARGE = 18
    BATTERY1_MODEL_NAME = 19
    BATTERY1_ON_BIKE_CHARGE_CYCLES = 20
    BATTERY1_OPTIMIZATION_MAXSOC = 21
    BATTERY1_PRODUCTION_DATE = 22
    BATTERY1_REMAINING_CAPACITY = 23
    BATTERY1_SERIAL_NUMBER = 24
    BATTERY1_STATE_OF_CHARGE = 26
    BATTERY1_TEMPERATURE = 27
    BATTERY1_TOTAL_CHARGE_CYCLES = 28
    BATTERY1_VOLTAGE_LEVEL = 29

    # Battery 2
    BATTERY2_CHARGING_ACTIVE = 30
    BATTERY2_CURRENT_LEVEL = 31
    BATTERY2_DFU_CELL = 32
    BATTERY2_DFU_FW = 33
    BATTERY2_DFU_HW = 34
    BATTERY2_DFU_MCUTYPE = 35
    BATTERY2_DFU_PROJECT = 36
    BATTERY2_DFU_SAFETYSTATUS = 37
    BATTERY2_ERROR_CODES = 38
    BATTERY2_ERROR_CODES_2 = 40
    BATTERY2_FIRMWARE = 43
    BATTERY2_FULL_CAPACITY = 44
    BATTERY2_HARDWARE = 45
    BATTERY2_HEALTH = 46
    BATTERY2_MAX_UNCHARGE = 47
    BATTERY2_MODEL_NAME = 48
    BATTERY2_ON_BIKE_CHARGE_CYCLES = 49
    BATTERY2_PRODUCTION_DATE = 50
    BATTERY2_REMAINING_CAPACITY = 51
    BATTERY2_SERIAL_NUMBER = 52
    BATTERY2_STATE_OF_CHARGE = 54
    BATTERY2_TEMPERATURE = 55
    BATTERY2_TOTAL_CHARGE_CYCLES = 56
    BATTERY2_VOLTAGE_LEVEL = 57

    # Battery lock
    BATTERYLOCK_DATE = 58
    BATTERYLOCK_FW = 59
    BATTERYLOCK_HW = 60
    BATTERYLOCK_NAME = 61
    BATTERYLOCK_SN = 63
    BATTERYLOCK_STATUS = 65

    # Battery error masks
    BATTERY_ERROR_MASK2_FOR_DISPLAY = 66
    BATTERY_ERROR_MASK2_FOR_LOGGING = 67
    BATTERY_ERROR_MASK_FOR_DISPLAY = 68
    BATTERY_ERROR_MASK_FOR_LOGGING = 69
    BATTERY_SCHEDULE_CHARGING_ENABLE = 70
    BATTERY_SCHEDULE_CHARGING_START_TIME = 71
    BATTERY_SCHEDULE_CHARGING_STOP_TIME = 72

    # Bike frame lock
    BIKEFRAMELOCK_DATE = 73
    BIKEFRAMELOCK_FW = 74
    BIKEFRAMELOCK_HW = 75
    BIKEFRAMELOCK_NAME = 76
    BIKEFRAMELOCK_SN = 78
    BIKEFRAMELOCK_STATUS = 80

    # Bike
    BIKE_ACTIVATION_STATUS = 81
    BIKE_HIGH_GEAR = 82
    BIKE_LOW_GEAR = 83

    # Brose motor
    BROSE_CAN_AUTH_STATE = 84
    BROSE_CAN_REQ_RESP_STATE = 85
    BROSE_GEAR_RATIO = 86
    BROSE_GEAR_RATIO_ENABLE = 87
    BROSE_HIGH_GEAR = 88
    BROSE_LOW_GEAR = 89
    BROSE_PARAM_ERR_CODE = 90
    BROSE_PARAM_PORT = 91
    BROSE_PARA_CRC = 92

    # Dropper post
    DROPPER_FW = 93
    DROPPER_HW = 94
    DROPPER_SN = 95
    DROPPER_STATUS = 96

    # Enviolo hub
    ENVIOLO_CAL_REQ = 97
    ENVIOLO_CAN_FW = 98
    ENVIOLO_CAN_FW_INTERNAL = 99
    ENVIOLO_CAN_FW_MAJOR = 100
    ENVIOLO_CAN_FW_MINOR = 101
    ENVIOLO_CAN_FW_PATCH = 102
    ENVIOLO_ERROR = 103
    ENVIOLO_ERROR_MASK_FOR_DISPLAY = 104
    ENVIOLO_ERROR_MASK_FOR_LOGGING = 105
    ENVIOLO_HHI_FW_INTERNAL = 107
    ENVIOLO_HHI_FW_MAJOR = 108
    ENVIOLO_HHI_FW_MINOR = 109
    ENVIOLO_HHI_FW_PATCH = 110
    ENVIOLO_MASK = 111
    ENVIOLO_STATUS = 112
    ENVIOLO_STATUS_MASK_FOR_DISPLAY = 113
    ENVIOLO_STATUS_MASK_FOR_LOGGING = 114

    # Heart rate
    HEART_RATE = 115
    HRM_ANT_STATUS = 116
    HRM_BLE_STATUS = 117
    HR_ZONE_THRESHOLD_0 = 118
    HR_ZONE_THRESHOLD_1 = 119
    HR_ZONE_THRESHOLD_2 = 120
    HR_ZONE_THRESHOLD_3 = 121
    HR_ZONE_THRESHOLD_4 = 122
    HR_ZONE_THRESHOLD_5 = 123

    # Jump detection
    JUMP_COUNTS = 124
    JUMP_DISTANCE = 125
    JUMP_DURATION = 126
    JUMP_FLOW = 127
    JUMP_FLOW_RATING = 128
    JUMP_STATS = 129
    JUMP_VDV = 130
    JUMP_VDV_PEAK = 131

    # Lights
    LIGHT_BRAKE_LIGHT = 132
    LIGHT_LOW_BEAM_BRIGHTNESS = 133
    LIGHT_MODE = 134

    # Lock
    LOCK_FW = 135
    LOCK_HW = 136
    LOCK_SN = 137
    LOCK_STATUS = 138

    # Motor
    MOTOR_ACCELERATION_RESPONSE = 139
    MOTOR_ACCELERATION_RESPONSE_CLONE = 140
    MOTOR_ACTIVE_CURRENT_SCALING = 141
    MOTOR_ACTIVE_PROFILE_SCALING = 142
    MOTOR_ACTIVE_TRAVEL_MODE = 143
    MOTOR_ALLOWED_MAX_SPEED_LIMIT = 145
    MOTOR_AUTHENTICATION_STATE = 146
    MOTOR_BIKE_CADENCE = 147
    MOTOR_BIKE_SPEED = 148
    MOTOR_CADENCE_CONTROL = 149
    MOTOR_CURRENT_SCALING_ECO_SETTING = 151
    MOTOR_CURRENT_SCALING_SMART_SETTING = 152
    MOTOR_CURRENT_SCALING_TRAIL_SETTING = 153
    MOTOR_CURRENT_SCALING_TURBO_SETTING = 154
    MOTOR_ERROR_CODES = 155
    MOTOR_ERROR_CODES_2 = 156
    MOTOR_ERROR_MASK_FOR_DISPLAY = 157
    MOTOR_ERROR_MASK_FOR_LOGGING = 158
    MOTOR_FIRMWARE = 161
    MOTOR_G3_AUTO_MICRO_TUNE = 162
    MOTOR_G3_BACK_PEDALING = 163
    MOTOR_G3_DRIVE_ID = 164
    MOTOR_G3_DRIVE_TYPE = 165
    MOTOR_G3_ELEC_HW = 166
    MOTOR_G3_ELEC_SN = 167
    MOTOR_G3_KEY_ID = 169
    MOTOR_G3_MOTOR_SN2 = 170
    MOTOR_G3_OVERRUN = 171
    MOTOR_G3_SENSITIVITY = 172
    MOTOR_G3_SHUTTLE_MODE = 173
    MOTOR_G3_WAM_TUNE = 174
    MOTOR_GEAR_RATIO = 175
    MOTOR_HARDWARE_EXTENDED = 176
    MOTOR_ID = 178
    MOTOR_M20TQS_FIRMWARE = 179
    MOTOR_M20TQS_SERIALNUMBER = 180
    MOTOR_MAX_SPEED_LIMIT = 181
    MOTOR_ODOMETER = 182
    MOTOR_ODOMETER_OFFSET = 183
    MOTOR_PARA_VERSION = 184
    MOTOR_PLW_WARRANTY = 185
    MOTOR_POWER = 186
    MOTOR_PROFILE_SCALING_ECO_SETTING = 187
    MOTOR_PROFILE_SCALING_SMART_SETTING = 188
    MOTOR_PROFILE_SCALING_TRAIL_SETTING = 189
    MOTOR_PROFILE_SCALING_TURBO_SETTING = 190
    MOTOR_RIDER_INPUT_POWER = 191
    MOTOR_SECONDARY_MAX_SPEED_LIMIT = 192
    MOTOR_SECONDARY_MAX_SPEED_LIMIT_DEFAULT = 193
    MOTOR_SERIAL_NUMBER = 194
    MOTOR_TEMPERATURE = 196
    MOTOR_TEMPERATURE_CLONE = 197
    MOTOR_TQS_DRIVE_TYPE = 198
    MOTOR_TQS_FIRMWARE = 199
    MOTOR_TQS_HARDWARE = 200
    MOTOR_TQS_ID_NAME = 201
    MOTOR_TQS_SERIALNUMBER = 202
    MOTOR_WHEEL_SIZE = 203

    # PLW (pedal assist)
    PLW_CALIBRATION_SUPPORT = 204
    PLW_MOTOR_ANGLE = 205
    PLW_MOTOR_ANGLE_TORQUE = 206
    PLW_MOTOR_TORQUE = 207

    # Radar
    RADAR_ERROR = 208
    RADAR_ERROR_MASK = 209
    RADAR_ERROR_MASK_FOR_DISPLAY = 210
    RADAR_ERROR_MASK_FOR_LOGGING = 211
    RADAR_FW = 213
    RADAR_HW = 214
    RADAR_SN = 215
    RADAR_STATUS = 216

    # Remote
    REMOTE_BATTERY = 217
    REMOTE_DATECODE = 218
    REMOTE_FOX_SN = 219
    REMOTE_FOX_STATUS = 220
    REMOTE_FW = 221
    REMOTE_HW = 222
    REMOTE_SN = 223
    REMOTE_STATUS = 224

    # Shimano
    SHIMANO_EX_FW = 226
    SHIMANO_EX_PROTOCOL = 227
    SHIMANO_EX_SHIFT_BAT_LEVEL = 228
    SHIMANO_EX_SHIFT_MODE = 229
    SHIMANO_EX_SHIFT_POS = 230
    SHIMANO_EX_SHIFT_TEETH = 231
    SHIMANO_EX_SHIFT_TYPE = 232
    SHIMANO_LOCAL_PROTOCOL = 233
    SHIMANO_STATUS = 234
    SHIMANO_VERSIONS = 235

    # Smart junction box
    SMARTJUNCTIONBOX_FW = 236
    SMARTJUNCTIONBOX_HW = 237
    SMARTJUNCTIONBOX_SN = 238

    # System
    SYSTEM_ACCELERATION_RESPONSE_TURBO_BIKE = 240
    SYSTEM_ACTIVATION = 241
    SYSTEM_ALT = 242
    SYSTEM_ALTITUDE_CALIBRATION = 243
    SYSTEM_ALT_DESCENT = 244
    SYSTEM_ALT_GAIN = 245
    SYSTEM_ANTI_TAMPERING_TH_CAD = 246
    SYSTEM_ANTI_TAMPERING_TH_CAD_WHEEL = 247
    SYSTEM_ANT_DEVID = 248
    SYSTEM_ASSIST_MODE_ECO_TURBO_BIKE = 250
    SYSTEM_AUTO_OFF = 253
    SYSTEM_BACKUP_BATTERY_LAST_OFF_RTC = 254
    SYSTEM_BACKUP_BATTERY_LAST_OFF_VOLTAGE = 255
    SYSTEM_BACKUP_BATTERY_STATE = 256
    SYSTEM_BATTERIES_DISCHARGE_BEHAVIOUR = 257
    SYSTEM_BATTERY1_TYPE = 258
    SYSTEM_BATTERY2_TYPE = 259
    SYSTEM_BATTERYLOCK_TYPE = 260
    SYSTEM_BEEPER = 262
    SYSTEM_BIKEFRAMELOCK_TYPE = 263
    SYSTEM_BIKE_DOMAIN = 264
    SYSTEM_BIKE_ERROR_MASK = 267
    SYSTEM_BIKE_ERROR_MASK2 = 268
    SYSTEM_BIKE_ERROR_MASK_FOR_DISPLAY = 269
    SYSTEM_BIKE_ERROR_MASK_FOR_LOGGING = 270
    SYSTEM_BIKE_TYPE = 271
    SYSTEM_CAN_AUTH_READ_KEY = 272
    SYSTEM_CAN_AUTH_REQUEST = 273
    SYSTEM_CAN_AUTH_RESPONSE = 274
    SYSTEM_CAN_AUTH_WRITE_KEY = 275
    SYSTEM_CAN_BAUD = 276
    SYSTEM_COMPONENT_CHANGED_REASON = 277
    SYSTEM_CONSUMPTION = 279
    SYSTEM_CURRENT_RIDEID = 280
    SYSTEM_CURRENT_SCREEN = 281
    SYSTEM_DARK_MODE = 282
    SYSTEM_DEFAULT_TRAVEL_MODE = 283
    SYSTEM_DFU_DATA = 284
    SYSTEM_DFU_DATA_ACK = 285
    SYSTEM_DFU_STATE = 286
    SYSTEM_DFU_SUPPORTING_INFO = 287
    SYSTEM_DISPLAY_BRIGHTNESS = 288
    SYSTEM_DISTANCE_UNITS = 289
    SYSTEM_EBIKE_SERIAL_NUMBER = 290
    SYSTEM_ENABLE_FLIGHT_RECORDING = 292
    SYSTEM_ENVIOLO_TYPE = 293
    SYSTEM_ERASE_FAILURE_LOG = 294
    SYSTEM_ERASE_LOG_REQ = 295
    SYSTEM_FAKE_CHANNEL = 296
    SYSTEM_FIND_MY = 297
    SYSTEM_FIRMWARE_BUNDLE_ID = 298
    SYSTEM_G3_MOTOR_DFU = 299
    SYSTEM_GPS_HEADING = 301
    SYSTEM_GRADIENT = 302
    SYSTEM_HMI_DATE_CODE = 303
    SYSTEM_HMI_ERRORS_CODE = 304
    SYSTEM_HMI_HW_INFO = 307
    SYSTEM_HMI_HW_VERSION = 308
    SYSTEM_HMI_SERIAL_NUMBER = 311
    SYSTEM_HMI_STATUS = 312
    SYSTEM_HMI_SW_CAN_VERSION = 313
    SYSTEM_HMI_SW_VERSION = 314
    SYSTEM_HOUR_FORMAT_12_24 = 316
    SYSTEM_INFINITE_TUNE_STEP = 317
    SYSTEM_JUMP_DETECTION_ENABLE = 319
    SYSTEM_KCAL = 320
    SYSTEM_KEY_VIBRATION = 321
    SYSTEM_LANGUAGE = 322
    SYSTEM_LOCK_TYPE = 323
    SYSTEM_LOCK_UNLOCK = 324
    SYSTEM_LOG_DATA = 325
    SYSTEM_LOG_DATA_ACK = 326
    SYSTEM_MAX_HR = 327
    SYSTEM_MODEL_STRING = 328
    SYSTEM_MOTOR_TYPE = 329
    SYSTEM_NAK_RESPONSE = 330
    SYSTEM_NOT_ACTIVATED = 331
    SYSTEM_OVERBOOST_FLAG = 332
    SYSTEM_PLAYSOUNDS = 333
    SYSTEM_POWER_COMPENSATION = 334
    SYSTEM_RADAR_BEEP = 335
    SYSTEM_RADAR_BEEP_ACTIVE_SPEED = 336
    SYSTEM_RADAR_BEEP_CARCLEAR_ENABLE = 337
    SYSTEM_RADAR_PAGE = 338
    SYSTEM_RADAR_TYPE = 339
    SYSTEM_RADAR_VIBRATOR = 340
    SYSTEM_RANGE_LONG = 341
    SYSTEM_RANGE_SHORT = 342
    SYSTEM_RANGE_TREND = 343
    SYSTEM_READ_ACCOUNT_STRING = 344
    SYSTEM_READ_SCREEN_CONFIGURATION = 345
    SYSTEM_REAL_TIME_DATA_ENB = 346
    SYSTEM_REAL_TIME_RIDE_DATA = 347
    SYSTEM_RECORD_IN_PROCESS = 348
    SYSTEM_RECORD_STATUS_ICON = 349
    SYSTEM_RECORD_STATUS_OVR = 350
    SYSTEM_RECORD_STOP_REQ = 351
    SYSTEM_REDUCEPOWER_ACTIVE = 352
    SYSTEM_RESET_RIDE = 353
    SYSTEM_RIDE_DATA = 354
    SYSTEM_RIDE_DATA_ACK = 355
    SYSTEM_RTC = 357
    SYSTEM_SERVICEDUE_ACTIVE = 358
    SYSTEM_SERVICEDUE_ID = 359
    SYSTEM_SERVICEDUE_NEXTDATE = 360
    SYSTEM_SMARTJUNCTIONBOX_TYPE = 361
    SYSTEM_SPEED_LIMIT_STRING = 362
    SYSTEM_STATE = 363
    SYSTEM_STATUS = 364
    SYSTEM_SUPPORTED_TRAVEL_MODES = 366
    SYSTEM_TAMPERING = 367
    SYSTEM_TARGET_CAD = 368
    SYSTEM_TARGET_HPR = 369
    SYSTEM_TARGET_RIDER_POWER = 370
    SYSTEM_TEMPERATURE = 371
    SYSTEM_TILE_DEACTIVATE_TIMESTAMP = 372
    SYSTEM_TILE_ENABLE = 373
    SYSTEM_TILE_ID = 374
    SYSTEM_TILE_STATUS = 375
    SYSTEM_TIME_ZONE = 376
    SYSTEM_UNLOCK_BAT_IN_OFF = 377
    SYSTEM_USER_ID = 401
    SYSTEM_WRITE_ACCOUNT_STRING = 402
    SYSTEM_WRITE_SCREEN_CONFIGURATION = 403
    SYSTEM_YEAR_STRING = 404

    # Temperature statistics
    TEMP_STATISTIC_T0 = 405
    TEMP_STATISTIC_T1 = 406
    TEMP_STATISTIC_T2 = 407
    TEMP_STATISTIC_T3 = 408
    TEMP_STATISTIC_T4 = 409
    TEMP_STATISTIC_T5 = 410
    TEMP_STATISTIC_T6 = 411
    TEMP_STATISTIC_T7 = 412

    # Other
    TEST_FLEET_ACTIVATION_DEADLINE = 413
    VDV_STATS = 414

    # Identification sequence special value
    SYSTEM_GET_NEW_VI = 300


# ---------------------------------------------------------------------------
# TCX parameter metadata (telemetry-relevant subset)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TCXFieldDefinition:
    """Metadata for a telemetry parameter in the TCX2+ protocol."""

    param: BikeParameter
    name: str
    unit: str
    data_size: int  # bytes of payload after the 2-byte parameter ID
    convert: Callable[[int], float | int]
    writable: bool = False
    encode: Callable[[float | int], int] | None = None

    @property
    def param_id(self) -> int:
        return int(self.param)


_TCX_FIELDS: dict[int, TCXFieldDefinition] = {}


def _identity(v: int) -> int:
    """Identity conversion (no-op)."""
    return v


def _tcx(
    param: BikeParameter,
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
    fd = TCXFieldDefinition(
        param=param,
        name=name,
        unit=unit,
        data_size=size,
        convert=convert,
        writable=writable,
        encode=encode,
    )
    _TCX_FIELDS[fd.param_id] = fd


# --- Battery 1 ---
_tcx(BikeParameter.BATTERY1_STATE_OF_CHARGE, "battery_charge_percent", "%", 1)
_tcx(BikeParameter.BATTERY1_TEMPERATURE, "battery_temp", "°C", 1)
_tcx(
    BikeParameter.BATTERY1_VOLTAGE_LEVEL,
    "battery_voltage",
    "V",
    2,
    lambda v: v / 1000.0,
)
_tcx(
    BikeParameter.BATTERY1_CURRENT_LEVEL,
    "battery_current",
    "A",
    2,
    lambda v: v / 1000.0,
)
_tcx(BikeParameter.BATTERY1_HEALTH, "battery_health", "%", 1)
_tcx(BikeParameter.BATTERY1_FULL_CAPACITY, "battery_capacity_wh", "Wh", 2)
_tcx(BikeParameter.BATTERY1_REMAINING_CAPACITY, "battery_remaining_wh", "Wh", 2)
_tcx(BikeParameter.BATTERY1_TOTAL_CHARGE_CYCLES, "battery_charge_cycles", "cycles", 2)
_tcx(BikeParameter.BATTERY1_CHARGING_ACTIVE, "battery_charging_active", "", 1)
_tcx(
    BikeParameter.BATTERY1_ON_BIKE_CHARGE_CYCLES,
    "battery_on_bike_charge_cycles",
    "cycles",
    2,
)

# --- Battery 2 ---
_tcx(BikeParameter.BATTERY2_STATE_OF_CHARGE, "battery2_charge_percent", "%", 1)
_tcx(BikeParameter.BATTERY2_TEMPERATURE, "battery2_temp", "°C", 1)
_tcx(
    BikeParameter.BATTERY2_VOLTAGE_LEVEL,
    "battery2_voltage",
    "V",
    2,
    lambda v: v / 1000.0,
)
_tcx(
    BikeParameter.BATTERY2_CURRENT_LEVEL,
    "battery2_current",
    "A",
    2,
    lambda v: v / 1000.0,
)
_tcx(BikeParameter.BATTERY2_HEALTH, "battery2_health", "%", 1)
_tcx(BikeParameter.BATTERY2_FULL_CAPACITY, "battery2_capacity_wh", "Wh", 2)
_tcx(BikeParameter.BATTERY2_REMAINING_CAPACITY, "battery2_remaining_wh", "Wh", 2)
_tcx(BikeParameter.BATTERY2_TOTAL_CHARGE_CYCLES, "battery2_charge_cycles", "cycles", 2)

# --- Motor / rider ---
_tcx(BikeParameter.MOTOR_BIKE_CADENCE, "cadence", "RPM", 2, lambda v: v / 10.0)
_tcx(BikeParameter.MOTOR_BIKE_SPEED, "speed", "km/h", 2, lambda v: v / 10.0)
_tcx(BikeParameter.MOTOR_ODOMETER, "odometer", "km", 4, lambda v: v / 1000.0)
_tcx(BikeParameter.MOTOR_POWER, "motor_power", "W", 2)
_tcx(BikeParameter.MOTOR_RIDER_INPUT_POWER, "rider_power", "W", 2)
_tcx(BikeParameter.MOTOR_TEMPERATURE, "motor_temp", "°C", 1)
_tcx(
    BikeParameter.MOTOR_ACTIVE_TRAVEL_MODE,
    "assist_level",
    "",
    1,
    writable=True,
    encode=lambda v: int(v),
)
_tcx(
    BikeParameter.MOTOR_MAX_SPEED_LIMIT,
    "max_speed_limit",
    "km/h",
    2,
    lambda v: v / 10.0,
    writable=True,
    encode=lambda v: int(v * 10),
)
_tcx(
    BikeParameter.MOTOR_WHEEL_SIZE,
    "wheel_circumference",
    "mm",
    2,
    writable=True,
    encode=lambda v: int(v),
)
_tcx(
    BikeParameter.MOTOR_ACCELERATION_RESPONSE,
    "acceleration",
    "%",
    2,
    lambda v: (v - 3000) / 60.0,
    writable=True,
    encode=lambda v: int(v * 60 + 3000),
)

# --- System ---
_tcx(BikeParameter.SYSTEM_STATE, "system_state", "", 1)
_tcx(BikeParameter.SYSTEM_RANGE_LONG, "range_long", "km", 2, lambda v: v / 10.0)
_tcx(BikeParameter.SYSTEM_RANGE_SHORT, "range_short", "km", 2, lambda v: v / 10.0)
_tcx(BikeParameter.SYSTEM_RANGE_TREND, "range_trend", "", 1)
_tcx(BikeParameter.SYSTEM_TEMPERATURE, "system_temp", "°C", 1)
_tcx(BikeParameter.SYSTEM_CONSUMPTION, "consumption", "Wh/km", 2)
_tcx(BikeParameter.SYSTEM_KCAL, "kcal", "kcal", 2)
_tcx(BikeParameter.SYSTEM_ALT, "altitude", "m", 2)
_tcx(BikeParameter.SYSTEM_ALT_GAIN, "altitude_gain", "m", 2)
_tcx(BikeParameter.SYSTEM_ALT_DESCENT, "altitude_descent", "m", 2)
_tcx(BikeParameter.SYSTEM_GRADIENT, "gradient", "%", 2, lambda v: v / 10.0)

# --- Identification ---
_tcx(BikeParameter.SYSTEM_HMI_HW_VERSION, "hmi_hw_version", "", 4)
_tcx(BikeParameter.SYSTEM_HMI_SW_VERSION, "hmi_sw_version", "", 4)
_tcx(BikeParameter.SYSTEM_BIKE_TYPE, "bike_type", "", 1)
_tcx(BikeParameter.SYSTEM_MOTOR_TYPE, "motor_type", "", 1)
_tcx(BikeParameter.SYSTEM_EBIKE_SERIAL_NUMBER, "ebike_serial", "", 16)


def get_tcx_field(param_id: int) -> TCXFieldDefinition | None:
    """Return the field definition for a TCX parameter ID, or ``None``."""
    return _TCX_FIELDS.get(param_id)


def all_tcx_fields() -> dict[int, TCXFieldDefinition]:
    """Return a copy of all registered TCX field definitions."""
    return dict(_TCX_FIELDS)


# ---------------------------------------------------------------------------
# Wire encoding helpers
# ---------------------------------------------------------------------------


def encode_parameter_id(param_id: int) -> bytes:
    """Encode a parameter ID as 2 bytes big-endian for the TCX wire format."""
    return param_id.to_bytes(2, "big")


def decode_parameter_id(data: bytes | bytearray) -> int:
    """Decode a 2-byte big-endian parameter ID from the wire."""
    return int.from_bytes(data[:2], "big")
