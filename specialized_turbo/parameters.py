"""
BikeParameter definitions for Specialized Turbo TCX2/TCX3/TCX4 protocols.

The TCX2+ protocol addresses telemetry fields by a flat 16-bit parameter ID
(sent big-endian on the wire) instead of the TCU1 sender/channel pairs.

Parameter IDs and names were extracted from the Specialized Mission Control
Android app (``com.specialized.turboconnect.model.BikeParameter``).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum

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
    DROPPER_COUNT = 93
    DROPPER_FW = 94
    DROPPER_HW = 95
    DROPPER_SN = 96
    DROPPER_STATUS = 97

    # Enviolo hub
    ENVIOLO_CAL_REQ = 98
    ENVIOLO_CAN_FW = 99
    ENVIOLO_CAN_FW_INTERNAL = 100
    ENVIOLO_CAN_FW_MAJOR = 101
    ENVIOLO_CAN_FW_MINOR = 102
    ENVIOLO_CAN_FW_PATCH = 103
    ENVIOLO_ERROR = 104
    ENVIOLO_ERROR_MASK_FOR_DISPLAY = 105
    ENVIOLO_ERROR_MASK_FOR_LOGGING = 106
    ENVIOLO_HHI_FW_INTERNAL = 108
    ENVIOLO_HHI_FW_MAJOR = 109
    ENVIOLO_HHI_FW_MINOR = 110
    ENVIOLO_HHI_FW_PATCH = 111
    ENVIOLO_MASK = 112
    ENVIOLO_STATUS = 113
    ENVIOLO_STATUS_MASK_FOR_DISPLAY = 114
    ENVIOLO_STATUS_MASK_FOR_LOGGING = 115

    # Heart rate
    HEART_RATE = 116
    HRM_ANT_STATUS = 117
    HRM_BLE_STATUS = 118
    HR_ZONE_THRESHOLD_0 = 119
    HR_ZONE_THRESHOLD_1 = 120
    HR_ZONE_THRESHOLD_2 = 121
    HR_ZONE_THRESHOLD_3 = 122
    HR_ZONE_THRESHOLD_4 = 123
    HR_ZONE_THRESHOLD_5 = 124

    # Jump detection
    JUMP_COUNTS = 125
    JUMP_DISTANCE = 126
    JUMP_DURATION = 127
    JUMP_FLOW = 128
    JUMP_FLOW_RATING = 129
    JUMP_STATS = 130
    JUMP_VDV = 131
    JUMP_VDV_PEAK = 132

    # Lights
    LIGHT_BRAKE_LIGHT = 133
    LIGHT_LOW_BEAM_BRIGHTNESS = 134
    LIGHT_MODE = 135

    # Lock
    LOCK_HW = 137
    LOCK_SN = 138
    LOCK_STATUS = 139

    # Motor
    MOTOR_ACCELERATION_RESPONSE = 140
    MOTOR_ACCELERATION_RESPONSE_CLONE = 141
    MOTOR_ACTIVE_CURRENT_SCALING = 142
    MOTOR_ACTIVE_PROFILE_SCALING = 143
    MOTOR_ACTIVE_TRAVEL_MODE = 144
    MOTOR_ALLOWED_MAX_SPEED_LIMIT = 146
    MOTOR_AUTHENTICATION_STATE = 147
    MOTOR_BIKE_CADENCE = 148
    MOTOR_BIKE_SPEED = 149
    MOTOR_CADENCE_CONTROL = 150
    MOTOR_CURRENT_SCALING_ECO_SETTING = 152
    MOTOR_CURRENT_SCALING_SMART_SETTING = 153
    MOTOR_CURRENT_SCALING_TRAIL_SETTING = 154
    MOTOR_CURRENT_SCALING_TURBO_SETTING = 155
    MOTOR_ERROR_CODES = 156
    MOTOR_ERROR_CODES_2 = 157
    MOTOR_ERROR_MASK_FOR_DISPLAY = 158
    MOTOR_ERROR_MASK_FOR_LOGGING = 159
    MOTOR_FIRMWARE = 162
    MOTOR_G3_AUTO_MICRO_TUNE = 163
    MOTOR_G3_BACK_PEDALING = 164
    MOTOR_G3_DRIVE_ID = 165
    MOTOR_G3_DRIVE_TYPE = 166
    MOTOR_G3_ELEC_HW = 167
    MOTOR_G3_ELEC_SN = 168
    MOTOR_G3_KEY_ID = 170
    MOTOR_G3_MOTOR_SN2 = 171
    MOTOR_G3_OVERRUN = 172
    MOTOR_G3_SENSITIVITY = 173
    MOTOR_G3_SHUTTLE_MODE = 174
    MOTOR_G3_WAM_TUNE = 175
    MOTOR_GEAR_RATIO = 176
    MOTOR_HARDWARE_EXTENDED = 177
    MOTOR_ID = 179
    MOTOR_M20TQS_FIRMWARE = 180
    MOTOR_M20TQS_SERIALNUMBER = 181
    MOTOR_MAX_SPEED_LIMIT = 182
    MOTOR_ODOMETER = 183
    MOTOR_ODOMETER_OFFSET = 184
    MOTOR_PLW_WARRANTY = 186
    MOTOR_POWER = 187
    MOTOR_PROFILE_SCALING_ECO_SETTING = 188
    MOTOR_PROFILE_SCALING_SMART_SETTING = 189
    MOTOR_PROFILE_SCALING_TRAIL_SETTING = 190
    MOTOR_PROFILE_SCALING_TURBO_SETTING = 191
    MOTOR_RIDER_INPUT_POWER = 192
    MOTOR_SECONDARY_MAX_SPEED_LIMIT = 193
    MOTOR_SECONDARY_MAX_SPEED_LIMIT_DEFAULT = 194
    MOTOR_SERIAL_NUMBER = 195
    MOTOR_TEMPERATURE = 197
    MOTOR_TEMPERATURE_CLONE = 198
    MOTOR_TQS_DRIVE_TYPE = 199
    MOTOR_TQS_FIRMWARE = 200
    MOTOR_TQS_HARDWARE = 201
    MOTOR_TQS_ID_NAME = 202
    MOTOR_TQS_SERIALNUMBER = 203
    MOTOR_WHEEL_SIZE = 204

    # PLW (pedal assist)
    PLW_CALIBRATION_SUPPORT = 205
    PLW_MOTOR_ANGLE = 206
    PLW_MOTOR_ANGLE_TORQUE = 207
    PLW_MOTOR_TORQUE = 208

    # Radar
    RADAR_ERROR = 209
    RADAR_ERROR_MASK = 210
    RADAR_ERROR_MASK_FOR_DISPLAY = 211
    RADAR_ERROR_MASK_FOR_LOGGING = 212
    RADAR_FW = 214
    RADAR_HW = 215
    RADAR_SN = 216
    RADAR_STATUS = 217

    # Remote
    REMOTE_BATTERY = 218
    REMOTE_DATECODE = 219
    REMOTE_FOX_SN = 220
    REMOTE_FOX_STATUS = 221
    REMOTE_FW = 222
    REMOTE_HW = 223
    REMOTE_SN = 224
    REMOTE_STATUS = 225

    # Shimano
    SHIMANO_EX_FW = 227
    SHIMANO_EX_PROTOCOL = 228
    SHIMANO_EX_SHIFT_BAT_LEVEL = 229
    SHIMANO_EX_SHIFT_MODE = 230
    SHIMANO_EX_SHIFT_POS = 231
    SHIMANO_EX_SHIFT_TEETH = 232
    SHIMANO_EX_SHIFT_TYPE = 233
    SHIMANO_LOCAL_PROTOCOL = 234
    SHIMANO_STATUS = 235
    SHIMANO_VERSIONS = 236

    # Smart junction box
    SMARTJUNCTIONBOX_FW = 237
    SMARTJUNCTIONBOX_HW = 238
    SMARTJUNCTIONBOX_SN = 239

    # System
    SYSTEM_ACCELERATION_RESPONSE_TURBO_BIKE = 241
    SYSTEM_ACTIVATION = 242
    SYSTEM_ALT = 243
    SYSTEM_ALTITUDE_CALIBRATION = 244
    SYSTEM_ALT_DESCENT = 245
    SYSTEM_ALT_GAIN = 246
    SYSTEM_ANTI_TAMPERING_TH_CAD = 247
    SYSTEM_ANTI_TAMPERING_TH_CAD_WHEEL = 248
    SYSTEM_ANT_DEVID = 249
    SYSTEM_ASSIST_MODE_ECO_TURBO_BIKE = 251
    SYSTEM_AUTO_OFF = 254
    SYSTEM_BACKUP_BATTERY_LAST_OFF_RTC = 255
    SYSTEM_BACKUP_BATTERY_LAST_OFF_VOLTAGE = 256
    SYSTEM_BACKUP_BATTERY_STATE = 257
    SYSTEM_BATTERIES_DISCHARGE_BEHAVIOUR = 258
    SYSTEM_BATTERY1_TYPE = 259
    SYSTEM_BATTERY2_TYPE = 260
    SYSTEM_BATTERYLOCK_TYPE = 261
    SYSTEM_BEEPER = 263
    SYSTEM_BIKEFRAMELOCK_TYPE = 264
    SYSTEM_BIKE_DOMAIN = 265
    SYSTEM_BIKE_ERRORS_CODE = 266
    SYSTEM_BIKE_ERROR_MASK = 268
    SYSTEM_BIKE_ERROR_MASK2 = 269
    SYSTEM_BIKE_ERROR_MASK_FOR_DISPLAY = 270
    SYSTEM_BIKE_ERROR_MASK_FOR_LOGGING = 271
    SYSTEM_BIKE_TYPE = 272
    SYSTEM_CAN_AUTH_READ_KEY = 273
    SYSTEM_CAN_AUTH_REQUEST = 274
    SYSTEM_CAN_AUTH_RESPONSE = 275
    SYSTEM_CAN_AUTH_WRITE_KEY = 276
    SYSTEM_CAN_BAUD = 277
    SYSTEM_COMPONENT_CHANGED_REASON = 278
    SYSTEM_CONSUMPTION = 280
    SYSTEM_CURRENT_RIDEID = 281
    SYSTEM_CURRENT_SCREEN = 282
    SYSTEM_DARK_MODE = 283
    SYSTEM_DEFAULT_TRAVEL_MODE = 284
    SYSTEM_DFU_DATA = 285
    SYSTEM_DFU_DATA_ACK = 286
    SYSTEM_DFU_STATE = 287
    SYSTEM_DFU_SUPPORTING_INFO = 288
    SYSTEM_DISPLAY_BRIGHTNESS = 289
    SYSTEM_DISTANCE_UNITS = 290
    SYSTEM_EBIKE_SERIAL_NUMBER = 291
    SYSTEM_ENABLE_FLIGHT_RECORDING = 293
    SYSTEM_ENVIOLO_TYPE = 294
    SYSTEM_ERASE_FAILURE_LOG = 295
    SYSTEM_ERASE_LOG_REQ = 296
    SYSTEM_FAKE_CHANNEL = 297
    SYSTEM_FIND_MY = 298
    SYSTEM_FIRMWARE_BUNDLE_ID = 299
    SYSTEM_G3_MOTOR_DFU = 300
    SYSTEM_GPS_HEADING = 302
    SYSTEM_GRADIENT = 303
    SYSTEM_HMI_DATE_CODE = 304
    SYSTEM_HMI_ERRORS_CODE = 305
    SYSTEM_HMI_HW_INFO = 308
    SYSTEM_HMI_HW_VERSION = 309
    SYSTEM_HMI_PROTOCOL_VERSION = 311
    SYSTEM_HMI_SERIAL_NUMBER = 312
    SYSTEM_HMI_STATUS = 313
    SYSTEM_HMI_SW_CAN_VERSION = 314
    SYSTEM_HMI_SW_VERSION = 315
    SYSTEM_HOUR_FORMAT_12_24 = 317
    SYSTEM_INFINITE_TUNE_STEP = 318
    SYSTEM_JUMP_DETECTION_ENABLE = 320
    SYSTEM_KCAL = 321
    SYSTEM_KEY_VIBRATION = 322
    SYSTEM_LANGUAGE = 323
    SYSTEM_LOCK_TYPE = 324
    SYSTEM_LOCK_UNLOCK = 325
    SYSTEM_LOG_DATA = 326
    SYSTEM_LOG_DATA_ACK = 327
    SYSTEM_MAX_HR = 328
    SYSTEM_MODEL_STRING = 329
    SYSTEM_MOTOR_TYPE = 330
    SYSTEM_NAK_RESPONSE = 331
    SYSTEM_NOT_ACTIVATED = 332
    SYSTEM_OVERBOOST_FLAG = 333
    SYSTEM_PLAYSOUNDS = 334
    SYSTEM_POWER_COMPENSATION = 335
    SYSTEM_RADAR_BEEP = 336
    SYSTEM_RADAR_BEEP_ACTIVE_SPEED = 337
    SYSTEM_RADAR_BEEP_CARCLEAR_ENABLE = 338
    SYSTEM_RADAR_PAGE = 339
    SYSTEM_RADAR_TYPE = 340
    SYSTEM_RADAR_VIBRATOR = 341
    SYSTEM_RANGE_LONG = 342
    SYSTEM_RANGE_SHORT = 343
    SYSTEM_RANGE_TREND = 344
    SYSTEM_READ_ACCOUNT_STRING = 345
    SYSTEM_READ_SCREEN_CONFIGURATION = 346
    SYSTEM_REAL_TIME_DATA_ENB = 347
    SYSTEM_REAL_TIME_RIDE_DATA = 348
    SYSTEM_RECORD_IN_PROCESS = 349
    SYSTEM_RECORD_STATUS_ICON = 350
    SYSTEM_RECORD_STATUS_OVR = 351
    SYSTEM_RECORD_STOP_REQ = 352
    SYSTEM_REDUCEPOWER_ACTIVE = 353
    SYSTEM_RESET_RIDE = 354
    SYSTEM_RIDE_DATA = 355
    SYSTEM_RIDE_DATA_ACK = 356
    SYSTEM_RTC = 358
    SYSTEM_SERVICEDUE_ACTIVE = 359
    SYSTEM_SERVICEDUE_ID = 360
    SYSTEM_SERVICEDUE_NEXTDATE = 361
    SYSTEM_SMARTJUNCTIONBOX_TYPE = 362
    SYSTEM_SPEED_LIMIT_STRING = 363
    SYSTEM_STATE = 364
    SYSTEM_STATUS = 365
    SYSTEM_SUPPORTED_TRAVEL_MODES = 367
    SYSTEM_TAMPERING = 368
    SYSTEM_TARGET_CAD = 369
    SYSTEM_TARGET_HPR = 370
    SYSTEM_TARGET_RIDER_POWER = 371
    SYSTEM_TEMPERATURE = 372
    SYSTEM_TILE_DEACTIVATE_TIMESTAMP = 373
    SYSTEM_TILE_ENABLE = 374
    SYSTEM_TILE_ID = 375
    SYSTEM_TILE_STATUS = 376
    SYSTEM_TIME_ZONE = 377
    SYSTEM_UNLOCK_BAT_IN_OFF = 378
    SYSTEM_USER_ID = 405
    SYSTEM_WRITE_ACCOUNT_STRING = 406
    SYSTEM_WRITE_SCREEN_CONFIGURATION = 407
    SYSTEM_YEAR_STRING = 408

    # Temperature statistics
    TEMP_STATISTIC_T0 = 409
    TEMP_STATISTIC_T1 = 410
    TEMP_STATISTIC_T2 = 411
    TEMP_STATISTIC_T3 = 412
    TEMP_STATISTIC_T4 = 413
    TEMP_STATISTIC_T5 = 414
    TEMP_STATISTIC_T6 = 415
    TEMP_STATISTIC_T7 = 416

    # Other
    TEST_FLEET_ACTIVATION_DEADLINE = 417

    # Identification sequence special value
    SYSTEM_GET_NEW_VI = 301


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
