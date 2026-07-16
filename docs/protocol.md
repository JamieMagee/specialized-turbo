# Specialized Turbo BLE protocol reference

Specialized Turbo e-bikes (Vado, Levo, Creo) expose telemetry and configuration over Bluetooth Low Energy. The bike acts as the GATT server; your phone or computer connects as the client.

There are four protocol generations in the wild. They all use the same BLE GATT service and characteristic UUIDs, but differ in how they format messages on the wire:

| Generation | Internal name | Message format |
| --- | --- | --- |
| TCU1 | `ProtocolSessionTCU1` | `[sender][channel][data]`, no CRC, no encryption |
| TCX2 | `ProtocolSessionTCX2` | 2-byte parameter ID + CRC-16 + optional AES-128-CTR |
| TCX3 | `ProtocolSessionTCX3` | Same wire format as TCX2, different parameter set |
| TCX4 | `ProtocolSessionTCX4` | Same wire format as TCX2/TCX3, different parameter set |

Three communication patterns exist:

1. **Notifications** -- the bike pushes telemetry as values change
2. **Queries** -- TCU1 uses request-read; TCX uses write-without-response + notify
3. **Write** -- the client changes settings (assist level, etc.)

---

## BLE discovery

All generations advertise with at least one of these manufacturer data payloads:

### Nordic (company ID `0x0059`)

TCX2, TCX3, and TCX4 bikes. The payload starts with the ASCII string `"TURBOHMI2017"`:

```
Company ID: 59 00
Payload:    54 55 52 42 4f 48 4d 49 32 30 31 37 01 00 00 00 00
            T  U  R  B  O  H  M  I  2  0  1  7
```

### Apple iBeacon (company ID `0x004C`)

Some bikes put `"TURBOHMI"` inside an iBeacon frame under Apple's company ID instead of Nordic's. The Nordic payload is still present but contains unrelated data. Detection should check all manufacturer data payloads for the `TURBOHMI` magic, not just Nordic's.

### Simplo (company ID `0x020D`)

TCU1 bikes advertise with Simplo Technology's company ID. The device name is `"SPECIALIZED"` and the service UUID `0x1816` (Cycling Speed and Cadence) may be advertised.

### Detection

```python
ADVERTISING_MAGIC = b"TURBOHMI"

def detect_generation(manufacturer_data: dict[int, bytes]) -> str | None:
    for payload in manufacturer_data.values():
        if ADVERTISING_MAGIC in payload:
            return "tcx"  # TCX2, TCX3, or TCX4
    if 0x020D in manufacturer_data:
        return "tcu1"
    return None
```

The detection tells you TCU1 vs TCX. Telling TCX2 apart from TCX3 or TCX4 requires the identification handshake (section below).

---

## GATT UUIDs

TCU1 and TCX bikes share the same short IDs for services and characteristics, but with different 128-bit UUID bases.

### TURBOHMI UUID base (TCX2/TCX3/TCX4)

```
000000xx-3731-3032-494d-484f42525554
```

The trailing bytes decode to `TURBOHMI2017` reversed (`7102IMHOBRUT`).

### GIGATRONIK UUID base (TCU1)

```
000000xx-0000-4b49-4e4f-525441474947
```

The trailing bytes decode to `GIGATRONIK` reversed (`KINORTAGIG`).

### Services and characteristics

Each service has a READ/NOTIFY characteristic (`0x001S`) and a
WRITE_WITHOUT_RESPONSE characteristic (`0x002S`), where `S` is the service ID.
TCX never performs a GATT read during normal operation.

| Service | Purpose | Notify | Write without response |
| --- | --- | --- | --- |
| `0x0001` | Identification and parameter queries | `0x0011` | `0x0021` |
| `0x0002` | Ride logs and multi-packet commands | `0x0012` | `0x0022` |
| `0x0003` | Parameter writes and real-time data | `0x0013` | `0x0023` |

Expand short IDs with the appropriate UUID base. For example, characteristic `0x0013` on a TCX2 bike is `00000013-3731-3032-494d-484f42525554`.

---

## Authentication

### TCU1

No authentication. The GATT services are open.

### TCX2+

MITM protection and Secure Connections are required. The pairing flow:

1. Connect to the bike over BLE
2. Read the notification characteristic (`0x0013`) -- this triggers pairing
3. The bike's TCU shows a 6-digit PIN (passkey entry)
4. Enter the PIN to complete pairing
5. Bonded keys may be reused for subsequent connections

Some newer bikes use **numeric comparison** instead of passkey entry. The bike and the client both display a number and the user confirms they match. Bleak doesn't fully support this yet ([hbldh/bleak#1864](https://github.com/hbldh/bleak/pull/1864)), so on those bikes you need to pair through the OS first.

---

## TCU1 message format

TCU1 uses a straightforward byte layout with no framing:

```
[sender: 1 byte] [channel: 1 byte] [data: 1-4 bytes, little-endian]
```

TCU1 notifications are padded with `0xFF` to 20 bytes. The parser strips trailing `0xFF`.

### Senders

| Value | Name | Description |
| --- | --- | --- |
| `0x00` | BATTERY | Main battery |
| `0x01` | MOTOR | Motor controller and rider data |
| `0x02` | BIKE_SETTINGS | Bike configuration |
| `0x03` | (unknown) | Undocumented |
| `0x04` | BATTERY_2 | Secondary / range-extender battery (same channels as `0x00`) |

### Battery fields (sender `0x00` and `0x04`)

| Channel | Name | Size | Conversion | Unit | Example |
| --- | --- | --- | --- | --- | --- |
| `0x00` | Capacity | 2B | `round(raw * 1.1111)` | Wh | `00 00 c2 01` = 500 Wh |
| `0x01` | Remaining | 2B | `round(raw * 1.1111)` | Wh | `00 01 e4 00` = 253 Wh |
| `0x02` | Health | 1B | direct | % | `00 02 64` = 100% |
| `0x03` | Temperature | 1B | direct | C | `00 03 13` = 19 C |
| `0x04` | Charge cycles | 2B | direct | count | `00 04 0d 00` = 13 |
| `0x05` | Voltage | 1B | `raw / 5 + 20` | V | `00 05 50` = 36.0 V |
| `0x06` | Current | 1B | `raw / 5` | A | `00 06 00` = 0.0 A |
| `0x0C` | State of charge | 1B | direct | % | `00 0c 34` = 52% |

The voltage and current conversion formulas are approximate (noted in the Sepp62 reference). The 1.1111 Wh multiplier may vary by battery pack.

### Motor / rider fields (sender `0x01`)

| Channel | Name | Size | Conversion | Unit | Example |
| --- | --- | --- | --- | --- | --- |
| `0x00` | Rider power | 2B | direct | W | `01 00 c8 00` = 200 W |
| `0x01` | Cadence | 2B | `raw / 10` | RPM | `01 01 2c 03` = 81.2 RPM |
| `0x02` | Speed | 2B | `raw / 10` | km/h | `01 02 fa 00` = 25.0 km/h |
| `0x04` | Odometer | 4B | `raw / 1000` | km | `01 04 9e d1 39 00` = 3789.214 km |
| `0x05` | Assist level | 2B | enum (0=OFF, 1=ECO, 2=TRAIL, 3=TURBO) | | `01 05 02 00` = TRAIL |
| `0x07` | Motor temp | 1B | direct | C | `01 07 19` = 25 C |
| `0x0C` | Motor power | 2B | direct | W | `01 0c 64 00` = 100 W |
| `0x10` | Peak assist | 3B | three 1-byte values | % | `01 10 0a 14 32` = ECO=10%, TRAIL=20%, TURBO=50% |
| `0x15` | Shuttle | 1B | direct | | `01 15 00` = 0 |

### Bike settings fields (sender `0x02`)

| Channel | Name | Size | Conversion | Unit | Example |
| --- | --- | --- | --- | --- | --- |
| `0x00` | Wheel circumference | 2B | direct | mm | `02 00 fc 08` = 2300 mm |
| `0x03` | Assist lev 1 (ECO) | 1B | direct | % | `02 03 0a` = 10% |
| `0x04` | Assist lev 2 (TRAIL) | 1B | direct | % | `02 04 14` = 20% |
| `0x05` | Assist lev 3 (TURBO) | 1B | direct | % | `02 05 32` = 50% |
| `0x06` | Fake channel | 1B | bit-coded | | `02 06 00` = 0 |
| `0x07` | Acceleration | 2B | `(raw - 3000) / 60` | % | `02 07 a0 0f` = 16.67% |

Acceleration raw range is 3000-9000, mapping to 0-100%.

---

## TCX2+ message format

TCX2, TCX3, and TCX4 all use the same 20-byte packet format. The difference between generations is which `BikeParameter` IDs the bike supports -- the framing is identical.

### Packet layout

```
[payload: 18 bytes] [CRC-16: 2 bytes little-endian]
```

Total: always 20 bytes (the BLE ATT MTU).

The payload contains:

```
[param_id: 2 bytes big-endian] [data: 0-16 bytes little-endian] [zero padding]
```

The parameter ID is a 16-bit value from the `BikeParameter` enum (352 known values). It replaces the TCU1 sender/channel pair -- there's no sender byte, just a flat ID namespace.

### Processing pipeline

Outgoing (client to bike):

```
raw payload --> zero-pad to 18 bytes --> CRC-16 append --> AES-CTR encrypt --> BLE write
```

Incoming (bike to client):

```
BLE notify --> AES-CTR decrypt --> CRC-16 validate and strip --> parse parameter
```

Encryption is optional. Some older TCX2 bikes and all TCU1 bikes work without it. Whether encryption is needed depends on the identification handshake.

---

## CRC-16 framing

All TCX2+ packets carry a CRC-16 for integrity checking.

- **Algorithm**: CRC-16/CCITT-FALSE
- **Polynomial**: 0x1021
- **Initial value**: 0xFFFF
- **Final XOR**: none
- **Byte order**: the 2-byte CRC is stored **little-endian** at the end of the packet
- **Python**: `binascii.crc_hqx(data, 0xFFFF)` from the standard library

### Example

The packet `f8ff000c0500000000000000000000000000e6ca` breaks down as:

```
NAK marker:  f8 ff
Echoed ID:   00 0c   (parameter 12, requested by the host)
Reason code: 05
Zero-pad:    00 * 13
CRC-16 (LE): e6 ca   (0xCAE6)
```

This is a **NAK** (rejection) from the bike — see the next section.
Verifying: `crc_hqx(bytes.fromhex("f8ff000c0500000000000000000000000000"), 0xFFFF)` gives `0xCAE6`.

---

## AES-128-CTR encryption

Some TCX2+ bikes encrypt notifications and query responses with AES-128-CTR. The key is provisioned out-of-band by the account backend; the per-connection IV is installed during the identification handshake (see *Key source* below).

### Encrypted packet layout

```
[param_id: 2 bytes, CLEAR] [body: 18 bytes, ENCRYPTED]
```

The first two bytes (the parameter ID) are always in the clear. Bytes 2-19 are AES-128-CTR encrypted. Since CTR mode is symmetric, the same operation encrypts and decrypts.

### Packets that skip encryption

Even when encryption is active, these packets are always sent in the clear.
The native `ProtocolSession::isEncryptablePacket` is simply `*begin != 0x0A`,
so **any** packet whose first byte is `0x0A` bypasses encryption:

- **Legacy NAK**: a single `0x0A` byte (older TCU1/TCX1 negative acknowledgment)
- **`0x0Axx` control frames**: the identification control frames
  `SYSTEM_GET_NEW_VI` (wire `0x0A00`) and `SYSTEM_HMI_PROTOCOL_VERSION`
  (wire `0x0A01`). Their 2-byte wire id is sent big-endian, so the first byte
  is `0x0A`; the IV in the `0x0A00` response body is therefore readable in the
  clear. No other wire id uses `0x0A` as its high byte.
- **TCX2+ NAK envelope**: any packet starting with `0xF8 0xFF` — the bike's
  rejection format (a conservative superset of the native check)

### TCX2+ NAK rejections

When the bike rejects a request (wrong PIN, encryption required, parameter
unsupported, parameter currently unavailable, …) it responds with a 20-byte
NAK packet:

```
f8 ff [echoed_param_id_be: 2B] [reason_code: 1B] [zeros: 13B] [crc16_le: 2B]
```

The 2-byte parameter ID is the request that was rejected, echoed back. The
1-byte reason code indicates why. The library detects NAK packets via
`framing.is_nak_packet()` and surfaces them through `ParsedMessage.nak_reason`
rather than parsing the reason byte as if it were valid data.

### Key source

The encryption key is **not** exchanged over BLE. It comes from the bike's
`BTEncryptionInfo`, which is provisioned out-of-band by the Specialized
account backend (fetched from the keystore API and matched by HMI hardware /
serial). In particular, TCX parameter 14 (`BATTERY1_FIRMWARE`) is a **3-byte
firmware version**, *not* key material — an earlier version of this library
wrongly treated its response as a key.

What the bike *does* provide during identification is the AES-CTR **IV**: the
clear `SYSTEM_GET_NEW_VI` (`0x0A00`) response body carries the 16-byte IV.
The session key is the backend key; the session IV is this per-connection IV.

This library implements no account/login or network client of any kind for
acquiring that key: it is a caller-supplied input (see the `key` parameter of
`SpecializedConnection` and the CLI's `--key-file`, documented in the main
[README](../README.md#encryption-keys-key-file-format)), obtained by the
caller from an external, authorized source.

### Key derivation

The backend `BTEncryptionInfo.key` is a 64-character base64 string. Deriving
the final 16-byte AES key from it:

1. Start with the 64-character base64-encoded string from the backend
2. Base64-decode it (yields ~48 raw bytes)
3. The first 16 bytes are an intermediate AES key
4. The remaining bytes are AES-CTR decrypted using that intermediate key with a zero IV
5. The decrypted result is an ASCII hex string
6. Hex-decode that string to get the final 16-byte AES key

```python
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def derive_key(base64_key: str) -> bytes:
    raw = base64.b64decode(base64_key)
    intermediate = raw[:16]
    encrypted_rest = raw[16:]
    cipher = Cipher(algorithms.AES(intermediate), modes.CTR(b"\x00" * 16))
    decryptor = cipher.decryptor()
    hex_str = decryptor.update(encrypted_rest) + decryptor.finalize()
    return bytes.fromhex(hex_str.decode("ascii"))
```

---

## Identification handshake

Before streaming telemetry, TCX2+ bikes require a multi-step identification
sequence. Each step CRC-frames a 2-byte big-endian **wire command id** (mapped
from an app-level `BikeParameter` by generation/revision — see
`specialized_turbo/wire_profiles.py`), writes the 20-byte frame without
response to service 1 characteristic `0x0021`, and awaits the matching
notification on `0x0011`. Correlation is by wire id (a NAK echoes it).

Two steps are **clear** `0x0Axx` control frames; the rest are AES-CTR
encrypted (clear 2-byte header, encrypted body) using the backend key and the
IV installed in step 1.

### Full identification steps (new bike)

| Step | Param | Wire id | Clear/enc | Purpose |
| --- | --- | --- | --- | --- |
| 1 | `SYSTEM_GET_NEW_VI` (300) | `0x0A00` | clear | Request carries one zero byte; response body is the 16-byte AES-CTR **IV** |
| 2 | `SYSTEM_HMI_PROTOCOL_VERSION` (310) | `0x0A01` | clear | Response carries BLE + USB revision bytes; the BLE revision + generation selects the `ProtocolRevision` |
| 3 | `SYSTEM_STATE` (363) | `0x0801` | encrypted | System state (ready, sleeping, etc.) |
| 4 | `BATTERY1_FIRMWARE` (14) | `0x05F3` | encrypted | 3-byte **firmware version** (not a key) |
| 5 | `SYSTEM_HMI_HW_VERSION` (308) | `0x0807` | encrypted | HMI hardware version string |
| 6 | `SYSTEM_MOTOR_TYPE` (329) | revision-specific | encrypted | Motor type (wire id varies by revision, e.g. TCX2 rev `0x12` → `0x08D2`) |
| 7 | `SYSTEM_EBIKE_SERIAL_NUMBER` (290) | `0x0804` | encrypted | Serial number |

The encryption key itself is **not** part of this sequence — it is fetched
out-of-band from the account keystore (see *Key source* above). Step 1
installs the per-connection IV; the combination is what enables the encrypted
reads in steps 3–7.

The identification result determines the bike type, which maps to a protocol generation:

| Bike type | Name | Protocol generation |
| --- | --- | --- |
| 0 | PROTOTYPE | TCU1 (legacy) |
| 1 | TURBO | TCU1 (legacy) |
| 2 | LEVO1 | TCU1 (legacy) |
| 3 | VADO | TCU1 (legacy) |
| 4 | PLW | TCU1 (legacy) |
| 5 | LEVO2 | TCX (2019+) |
| 6 | COMO2 | TCX (2019+) |
| 7 | PLW2 | TCX (2019+) |
| 8 | APLW2 | TCX (2019+) |
| 9 | PLUTO | TCX (2019+) |
| 10 | APLUTO | TCX (2019+) |
| 11 | APLUTOPLUS | TCX (2019+) |
| 12 | PLUTO2 | TCX (2019+) |

At the transport layer, the app distinguishes only two protocol modes: TCU1 (types 0–4, legacy sender/channel format) and TCX (types 5–12, parameter ID format with CRC framing). The TCX2/TCX3/TCX4 distinction refers to which parameter IDs the bike supports, not the wire format — all TCX bikes use the same 20-byte CRC-framed packets.

---

## TCX2+ telemetry fields

The TCX2+ protocol uses 16-bit parameter IDs from the `BikeParameter` enum. There are 352 known parameter IDs. The table below lists the 44 that have telemetry conversion definitions in this library.

Note that conversions differ from TCU1 in several cases. TCX battery voltage and current are 2-byte millivolt/milliamp values (`raw / 1000`), while TCU1 uses 1-byte values with different scaling (`raw / 5 + 20` for voltage, `raw / 5` for current). TCX capacity is direct watt-hours; TCU1 uses a `1.1111` multiplier.

### Battery 1

| Param ID | Name | Field name | Unit | Size | Conversion |
| --- | --- | --- | --- | --- | --- |
| 0 | `BATTERY1_CHARGING_ACTIVE` | `battery_charging_active` | | 1B | direct |
| 1 | `BATTERY1_CURRENT_LEVEL` | `battery_current` | A | 2B | `raw / 1000` |
| 15 | `BATTERY1_FULL_CAPACITY` | `battery_capacity_wh` | Wh | 2B | direct |
| 17 | `BATTERY1_HEALTH` | `battery_health` | % | 1B | direct |
| 20 | `BATTERY1_ON_BIKE_CHARGE_CYCLES` | `battery_on_bike_charge_cycles` | cycles | 2B | direct |
| 23 | `BATTERY1_REMAINING_CAPACITY` | `battery_remaining_wh` | Wh | 2B | direct |
| 26 | `BATTERY1_STATE_OF_CHARGE` | `battery_charge_percent` | % | 1B | direct |
| 27 | `BATTERY1_TEMPERATURE` | `battery_temp` | C | 1B | direct |
| 28 | `BATTERY1_TOTAL_CHARGE_CYCLES` | `battery_charge_cycles` | cycles | 2B | direct |
| 29 | `BATTERY1_VOLTAGE_LEVEL` | `battery_voltage` | V | 2B | `raw / 1000` |

### Battery 2

| Param ID | Name | Field name | Unit | Size | Conversion |
| --- | --- | --- | --- | --- | --- |
| 31 | `BATTERY2_CURRENT_LEVEL` | `battery2_current` | A | 2B | `raw / 1000` |
| 44 | `BATTERY2_FULL_CAPACITY` | `battery2_capacity_wh` | Wh | 2B | direct |
| 46 | `BATTERY2_HEALTH` | `battery2_health` | % | 1B | direct |
| 51 | `BATTERY2_REMAINING_CAPACITY` | `battery2_remaining_wh` | Wh | 2B | direct |
| 54 | `BATTERY2_STATE_OF_CHARGE` | `battery2_charge_percent` | % | 1B | direct |
| 55 | `BATTERY2_TEMPERATURE` | `battery2_temp` | C | 1B | direct |
| 56 | `BATTERY2_TOTAL_CHARGE_CYCLES` | `battery2_charge_cycles` | cycles | 2B | direct |
| 57 | `BATTERY2_VOLTAGE_LEVEL` | `battery2_voltage` | V | 2B | `raw / 1000` |

### Motor and rider

| Param ID | Name | Field name | Unit | Size | Conversion |
| --- | --- | --- | --- | --- | --- |
| 139 | `MOTOR_ACCELERATION_RESPONSE` | `acceleration` | % | 2B | `(raw - 3000) / 60` |
| 143 | `MOTOR_ACTIVE_TRAVEL_MODE` | `assist_level` | | 1B | direct |
| 147 | `MOTOR_BIKE_CADENCE` | `cadence` | RPM | 2B | `raw / 10` |
| 148 | `MOTOR_BIKE_SPEED` | `speed` | km/h | 2B | `raw / 10` |
| 181 | `MOTOR_MAX_SPEED_LIMIT` | `max_speed_limit` | km/h | 2B | `raw / 10` |
| 182 | `MOTOR_ODOMETER` | `odometer` | km | 4B | `raw / 1000` |
| 186 | `MOTOR_POWER` | `motor_power` | W | 2B | direct |
| 191 | `MOTOR_RIDER_INPUT_POWER` | `rider_power` | W | 2B | direct |
| 196 | `MOTOR_TEMPERATURE` | `motor_temp` | C | 1B | direct |
| 203 | `MOTOR_WHEEL_SIZE` | `wheel_circumference` | mm | 2B | direct |

### System

| Param ID | Name | Field name | Unit | Size | Conversion |
| --- | --- | --- | --- | --- | --- |
| 242 | `SYSTEM_ALT` | `altitude` | m | 2B | direct |
| 244 | `SYSTEM_ALT_DESCENT` | `altitude_descent` | m | 2B | direct |
| 245 | `SYSTEM_ALT_GAIN` | `altitude_gain` | m | 2B | direct |
| 279 | `SYSTEM_CONSUMPTION` | `consumption` | Wh/km | 2B | direct |
| 302 | `SYSTEM_GRADIENT` | `gradient` | % | 2B | `raw / 10` |
| 320 | `SYSTEM_KCAL` | `kcal` | kcal | 2B | direct |
| 341 | `SYSTEM_RANGE_LONG` | `range_long` | km | 2B | `raw / 10` |
| 342 | `SYSTEM_RANGE_SHORT` | `range_short` | km | 2B | `raw / 10` |
| 343 | `SYSTEM_RANGE_TREND` | `range_trend` | | 1B | direct |
| 363 | `SYSTEM_STATE` | `system_state` | | 1B | direct |
| 371 | `SYSTEM_TEMPERATURE` | `system_temp` | C | 1B | direct |

### Identification parameters

These are read during the identification handshake, not during normal telemetry:

| Param ID | Name | Field name | Size |
| --- | --- | --- | --- |
| 271 | `SYSTEM_BIKE_TYPE` | `bike_type` | 1B |
| 290 | `SYSTEM_EBIKE_SERIAL_NUMBER` | `ebike_serial` | 16B |
| 308 | `SYSTEM_HMI_HW_VERSION` | `hmi_hw_version` | 4B |
| 314 | `SYSTEM_HMI_SW_VERSION` | `hmi_sw_version` | 4B |
| 329 | `SYSTEM_MOTOR_TYPE` | `motor_type` | 1B |

The full set of 352 `BikeParameter` IDs is defined in `parameters.py`. Most are for diagnostics, DFU (firmware updates), or subsystems like Shimano electronic shifting, Enviolo hubs, radar, and locks that this library doesn't parse yet.

---

## Communication patterns

### TCX notifications and queries

1. Subscribe to service 1 notifications (`0x0011`) before identification.
2. For each identification or read request:
   - Build `[param_id_hi, param_id_lo]`.
   - Zero-pad and append CRC-16 to make a 20-byte frame.
   - Encrypt the frame if the session negotiated AES-CTR.
   - Write it without response to service 1 characteristic `0x0021`.
   - Await the notification on `0x0011` whose parameter ID matches the request.
3. After identification, subscribe to service 3 (`0x0013`) and service 2
   (`0x0012`) notifications.
4. Start live telemetry by writing
   `SYSTEM_REAL_TIME_DATA_ENB` (`0x015A`) with value `0x01` to service 3:

   ```
   01 5a 01 [zero padding] [crc16_le]
   ```

   Write `0x00` to stop the stream.

Real-time ride data uses a separate multi-packet command family beginning
`f8 f4`. Each 20-byte BLE packet is decrypted and CRC-checked before
reassembly. The final packet has `0xff` in byte 2, and the reassembled data
contains parameter records whose values use the normal `BikeParameter`
metadata. The exact firmware-dependent record set and packet payload offset
still need confirmation from an untruncated live capture.

The official Android app performs no GATT reads for TCX. A GATT read produces
an `f8 ff` NAK response on affected bikes.

### TCU1 request-read

1. Write `[sender, channel]` to characteristic `0x0021` (service `0x0001`).
2. Read the response from characteristic `0x0011`.
3. Verify the response starts with the requested sender and channel.

The Sepp62 reference code unsubscribes from notifications before doing TCU1
request-reads since they can interfere on the same connection.

### Write commands (TCU1)

Write command bytes using the TCU1 command endpoint. TCX2+ parameter writes
use service 3 characteristic `0x0023`, write-without-response, and the same
CRC/encryption pipeline as queries.

Set assist level:

```
01 05 [level]
level: 0=OFF, 1=ECO, 2=TRAIL, 3=TURBO
```

Set assist percentage per level:

```
02 [03+i] [value]
i: 0=ECO, 1=TRAIL, 2=TURBO
value: 0-100
```

Set peak assist (all levels at once):

```
01 10 [eco%] [trail%] [turbo%] 32
```

Set acceleration:

```
02 07 [low] [high]
raw = (sensitivity * 60) + 3000, sent as 16-bit little-endian
range: 3000 (0%) to 9000 (100%)
```

Set shuttle:

```
01 15 [value]
value: 0-100
```

---

## Quirks

1. **Message `0x02 0x27`**: undocumented, but when it arrives on TCU1, notifications pause briefly. The Sepp62 reference uses this window to sneak in a request-read for battery capacity.

2. **Request-read interference**: on TCU1, do request-reads while notifications are paused to avoid garbled responses. TCX does not use GATT reads.

3. **TCU1 voltage/current formulas**: the conversions (`raw/5+20` for voltage, `raw/5` for current) are noted as approximate in the Sepp62 source. TCX2+ uses millivolt/milliamp values directly, which avoids this ambiguity.

4. **TCU1 battery Wh factor**: the `1.1111` multiplier may vary across battery packs. TCX2+ reports Wh directly.

---

## References

- [Sepp62/LevoEsp32Ble](https://github.com/Sepp62/LevoEsp32Ble) -- C++/ESP32 implementation (MIT). Primary source for TCU1 protocol details.
- [Micheledv74/turbolevo-pwa](https://github.com/Micheledv74/turbolevo-pwa) -- Web Bluetooth dashboard (TCU1)
- [paolovsrl/specialized_ble](https://github.com/paolovsrl/specialized_ble) -- ESP-IDF client (TCU1)
