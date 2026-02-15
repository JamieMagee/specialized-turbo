# Specialized Turbo BLE Protocol Reference

> **Protocol generation:** Gen 2 — "TURBOHMI2017"
> **Applicable models:** Specialized Turbo Vado, Levo, Creo, and other Turbo models with TCU (2017+)
> **Based on:** [Sepp62/LevoEsp32Ble](https://github.com/Sepp62/LevoEsp32Ble) (MIT license)

---

## 1. Overview

Specialized Turbo e-bikes communicate over Bluetooth Low Energy (BLE) using a proprietary GATT protocol. The bike acts as a **GATT server** (peripheral) and the client (phone/computer) connects as a **GATT client** (central).

The protocol supports three communication patterns:

1. **Notifications** (passive) — the bike continuously pushes telemetry data
2. **Request-Read** (active query) — the client requests a specific value
3. **Write** (commands) — the client changes settings (assist level, etc.)

---

## 2. BLE Discovery

### Advertising Data

The bike advertises using **Nordic Semiconductor** (company ID `0x0059`) manufacturer-specific data containing the ASCII string `"TURBOHMI"`:

| Field | Value |
| --- | --- |
| Company ID | `0x0059` (Nordic Semiconductor) |
| Payload bytes [0:8] | `54 55 52 42 4f 48 4d 49` = `"TURBOHMI"` |
| Payload bytes [8:12] | `32 30 31 37` = `"2017"` |
| Remaining bytes | Variable (device-specific flags) |

**Full advertising example:**

```plain
Company ID: 59 00
Payload:    54 55 52 42 4f 48 4d 49 32 30 31 37 01 00 00 00 00
```

### Detection Algorithm

```python
def is_specialized_bike(manufacturer_data: dict[int, bytes]) -> bool:
    payload = manufacturer_data.get(0x0059)  # Nordic company ID
    return payload is not None and b"TURBOHMI" in payload
```

---

## 3. UUID Structure

All service and characteristic UUIDs share a common 128-bit base:

```plain
000000xx-3731-3032-494d-484f42525554
```

The last 12 bytes (`3731-3032-494d-484f42525554`) decode as ASCII:

- Hex: `37 31 30 32 49 4d 48 4f 42 52 55 54`
- ASCII: `7102IMHOBRUT`
- Reversed: **`TURBOHMI2017`**

### Services

| Purpose | Short ID | Full UUID |
| --- | --- | --- |
| **Notification Data** | `0x0003` | `00000003-3731-3032-494d-484f42525554` |
| **Request / Query** | `0x0001` | `00000001-3731-3032-494d-484f42525554` |
| **Write / Commands** | `0x0002` | `00000002-3731-3032-494d-484f42525554` |

### Characteristics

| Service | Char Short ID | Full UUID | Properties | Purpose |
| --- | --- | --- | --- | --- |
| `0x0003` | `0x0013` | `00000013-3731-3032-494d-484f42525554` | READ, NOTIFY | Bike pushes telemetry here |
| `0x0001` | `0x0021` | `00000021-3731-3032-494d-484f42525554` | WRITE | Write request query here |
| `0x0001` | `0x0011` | `00000011-3731-3032-494d-484f42525554` | READ | Read query response here |
| `0x0002` | `0x0012` | `00000012-3731-3032-494d-484f42525554` | WRITE | Send commands here |

---

## 4. Authentication & Pairing

### Security Requirements

- **MITM protection** enabled
- **Secure Connections** enabled
- **IO capability:** Keyboard + Display (passkey entry)

### Pairing Flow

1. Client connects to the bike via BLE
2. Client attempts to **read** the notification characteristic (`0x0013`)
3. This triggers the BLE pairing/bonding process
4. The bike's **TCU** (Turbo Connect Unit) display shows a 6-digit numeric PIN
5. Client enters this PIN to complete pairing
6. Subsequent connections may use bonded keys (implementation-dependent)

### Connection Parameters

The bike requests:

- Interval: 25–50 ms (20–40 in 1.25ms units)
- Latency: 4
- Supervision timeout: 4000 ms

---

## 5. Message Format

All notifications, request-read responses, and write commands use the same basic structure:

```plain
[sender: 1 byte] [channel: 1 byte] [data: 1–4 bytes]
```

- **Sender** identifies the subsystem (battery, motor, settings)
- **Channel** identifies the specific data field within that subsystem
- **Data** is in **little-endian** byte order
- Maximum observed message length: 20 bytes (BLE ATT MTU constraint)

### Integer Extraction (Little-Endian)

| Size | Formula |
| --- | --- |
| 1 byte | `data[2]` |
| 2 bytes | `data[2] + (data[3] << 8)` |
| 4 bytes | `data[2] + (data[3] << 8) + (data[4] << 16) + (data[5] << 24)` |

---

## 6. Senders

| Value | Name | Description |
| --- | --- | --- |
| `0x00` | BATTERY | Main battery pack |
| `0x01` | MOTOR | Motor controller / rider data |
| `0x02` | BIKE_SETTINGS | Bike configuration |
| `0x03` | UNKNOWN | (undocumented) |
| `0x04` | BATTERY_2 | Secondary / range-extender battery (same channels as `0x00`) |

---

## 7. Data Fields

### 7.1 Battery (Sender `0x00` / `0x04`)

| Channel | Name | Size | Conversion | Unit | Example Hex | Example Value |
| --- | --- | --- | --- | --- | --- | --- |
| `0x00` | Capacity | 2B | `raw × 1.1111` (round) | Wh | `00 00 c2 01` | 500 Wh |
| `0x01` | Remaining | 2B | `raw × 1.1111` (round) | Wh | `00 01 e4 00` | 253 Wh |
| `0x02` | Health | 1B | direct | % | `00 02 64` | 100% |
| `0x03` | Temperature | 1B | direct | °C | `00 03 13` | 19°C |
| `0x04` | Charge Cycles | 2B | direct | count | `00 04 0d 00` | 13 |
| `0x05` | Voltage | 1B | `raw ÷ 5 + 20` | V | `00 05 50` | 36.0 V |
| `0x06` | Current | 1B | `raw ÷ 5` | A | `00 06 00` | 0.0 A |
| `0x0C` | State of Charge | 1B | direct | % | `00 0c 34` | 52% |

> **Note:** Voltage/current conversion formulas may be approximate.

### 7.2 Motor / Rider (Sender `0x01`)

| Channel | Name | Size | Conversion | Unit | Example Hex | Example Value |
| --- | --- | --- | --- | --- | --- | --- |
| `0x00` | Rider Power | 2B | direct | W | `01 00 c8 00` | 200 W |
| `0x01` | Cadence | 2B | `raw ÷ 10` | RPM | `01 01 2c 03` | 81.2 RPM |
| `0x02` | Speed | 2B | `raw ÷ 10` | km/h | `01 02 fa 00` | 25.0 km/h |
| `0x04` | Odometer | 4B | `raw ÷ 1000` | km | `01 04 9e d1 39 00` | 3789.214 km |
| `0x05` | Assist Level | 2B | enum | — | `01 05 02 00` | TRAIL |
| `0x07` | Motor Temp | 1B | direct | °C | `01 07 19` | 25°C |
| `0x0C` | Motor Power | 2B | direct | W | `01 0c 64 00` | 100 W |
| `0x10` | Peak Assist | 3B | 3 × 1-byte | % | `01 10 0a 14 32` | ECO=10, TRAIL=20, TURBO=50 |
| `0x15` | Shuttle | 1B | direct | — | `01 15 00` | 0 |

#### Assist Level Enum

| Value | Name |
| --- | --- |
| 0 | OFF |
| 1 | ECO |
| 2 | TRAIL |
| 3 | TURBO |

### 7.3 Bike Settings (Sender `0x02`)

| Channel | Name | Size | Conversion | Unit | Example Hex | Example Value |
| --- | --- | --- | --- | --- | --- | --- |
| `0x00` | Wheel Circumference | 2B | direct | mm | `02 00 fc 08` | 2300 mm |
| `0x03` | Assist Level 1 (ECO) | 1B | direct | % | `02 03 0a` | 10% |
| `0x04` | Assist Level 2 (TRAIL) | 1B | direct | % | `02 04 14` | 20% |
| `0x05` | Assist Level 3 (TURBO) | 1B | direct | % | `02 05 32` | 50% |
| `0x06` | Fake Channel | 1B | bit-coded | — | `02 06 00` | 0 |
| `0x07` | Acceleration | 2B | `(raw - 3000) ÷ 60` | % | `02 07 a0 0f` | 16.67% |

> **Acceleration range:** raw 3000–9000 maps to 0–100%.

---

## 8. Communication Patterns

### 8.1 Notifications (Passive Telemetry)

1. Subscribe to notifications on characteristic `0x0013` (service `0x0003`)
2. The bike continuously sends messages as data changes
3. Parse each notification using the message format above
4. Notifications include data from all senders — battery, motor, and settings

### 8.2 Request-Read (Active Query)

To explicitly query a specific value:

1. **Write** 2 bytes `[sender, channel]` to characteristic `0x0021` (service `0x0001`)
2. **Read** the response from characteristic `0x0011` (service `0x0001`)
3. The response follows the standard message format: `[sender, channel, data...]`
4. Verify the first 2 bytes match your request

**Important:** The reference implementation suggests unsubscribing from notifications before performing request-read operations, as they can interfere on the same connection.

### 8.3 Write Commands

Write command bytes to characteristic `0x0012` (service `0x0002`).

#### Set Assist Level

```plain
Bytes: [0x01] [0x05] [level]
level: 0=OFF, 1=ECO, 2=TRAIL, 3=TURBO
```

#### Set Assist Percentage Per Level

```plain
Bytes: [0x02] [0x03+i] [value]
i: 0=ECO, 1=TRAIL, 2=TURBO
value: 0–100 (percent)
```

#### Set Peak Assist (All Levels at Once)

```plain
Bytes: [0x01] [0x10] [eco%] [trail%] [turbo%] [0x32]
```

#### Set Acceleration Sensitivity

```plain
Bytes: [0x02] [0x07] [low_byte] [high_byte]
Raw value = (sensitivity × 60) + 3000
Sent as 16-bit little-endian
Range: 3000 (0%) to 9000 (100%)
```

#### Set Shuttle

```plain
Bytes: [0x01] [0x15] [value]
value: 0–100
```

---

## 9. Known Quirks

1. **Message `0x02 0x27`**: An undocumented message that, when received, causes a brief pause in notifications. The reference implementation uses this window to perform an async read of battery capacity.

2. **Notification interference**: Request-read operations should be performed while notifications are paused to avoid response corruption.

3. **Voltage/Current formulas**: The conversions `÷5+20` (voltage) and `÷5` (current) are noted as potentially approximate in the reference implementation.

4. **Battery Wh factor**: The `×1.1111` conversion factor for battery Wh values is specific to the battery pack configuration and may differ across models.

5. **Bonding**: The reference ESP32 implementation does not implement BLE bonding (`BLE_SM_PAIR_AUTHREQ_BOND` is commented out), requiring re-pairing on each connection.

---

## 10. Protocol Generations

There is an older protocol generation used by ~2015 Specialized bikes:

| Attribute | Gen 1 (GIGATRONIK) | Gen 2 (TURBOHMI2017) |
| --- | --- | --- |
| UUID Base | `0000xxxx-0000-4b49-4e4f-525441474947` | `000000xx-3731-3032-494d-484f42525554` |
| Device Name | `"SPECIALIZED"` | (uses manufacturer data) |
| Auth | None (open GATT) | MITM + Secure Connections + Passkey |
| Models | 2015 Turbo Levo | 2017+ Turbo Vado, Levo, Creo |

This library implements **Gen 2 only**.

---

## 11. References

- [Sepp62/LevoEsp32Ble](https://github.com/Sepp62/LevoEsp32Ble) — Primary source (C++/ESP32, MIT)
- [Micheledv74/turbolevo-pwa](https://github.com/Micheledv74/turbolevo-pwa) — Web Bluetooth dashboard (Gen 1)
- [paolovsrl/specialized_ble](https://github.com/paolovsrl/specialized_ble) — ESP-IDF client (Gen 1)
