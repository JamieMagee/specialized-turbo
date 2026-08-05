# Specialized Turbo BLE Protocol — Independent Verification Report

Verified by decompiling the Specialized Android app v1.66.0
(`com.specialized.turboconnect`) with jadx and analyzing the native
`libturbo-core.so` (272 MB ARM64) with string extraction.

---

## Executive Summary

The Python library (`specialized-turbo`) implements the Specialized Turbo BLE
protocol. GATT UUIDs, CRC-16 framing, AES-128-CTR encryption, key derivation,
the identification handshake, and the BikeParameter enum have been checked
against the decompiled Android app. A later HCI capture corrected one important
transport assumption: TCX queries use write-without-response plus notifications,
not GATT reads.

### Verification Status

| Area | Status | Notes |
|------|--------|-------|
| BikeParameter enum (352 IDs) | ✅ Verified | 348 exact matches; 4 in Python only, 1 in app only |
| GATT UUID bases | ✅ Verified | TURBOHMI and GIGATRONIK bases match exactly |
| Service short IDs (0x01/0x02/0x03) | ✅ Verified | |
| Characteristic short IDs (0x11/0x12/0x13/0x21/0x22/0x23) | ✅ Verified | Three notify/write pairs |
| TCX transaction model | ✅ Verified | Write without response, correlate notification |
| CRC-16/CCITT-FALSE | ✅ Verified | Native `CRC16Calculator` matches `crc_hqx` |
| AES-128-CTR encryption | ✅ Verified | `ProtocolEncryptionMethod.AES_CTR` confirmed |
| Key derivation pipeline | ✅ Verified | `BTEncryptionInfo.key` → base64 → AES → hex |
| Identification handshake | ✅ Verified | Full 7-step over write+notify |
| Packet size (20 bytes) | ✅ Verified | |
| F8FF NAK marker | ✅ Verified (was misinterpreted as envelope) | `ProtocolSessionTCX2::isNakPacket` checks for `F8 FF`; the library now detects it as a NAK rather than stripping it as a wrapper around valid data |
| NAK byte (0x0A) | ✅ Verified | Handled in native code |
| BLE advertisement detection | ✅ Verified | TURBOHMI magic, company IDs match |
| Field conversions | ✅ Verified | Ghidra: decoders skip 2B param ID, read param.length bytes |

---

## Detailed Findings

### 1. BikeParameter Enum

**Method**: Extracted all `(name, wire_id)` pairs from both the decompiled
`BikeParameter.java` (jadx) and `parameters.py` (Python IntEnum).

**Results**: 349 entries in app (excl. `UNKNOWN`), 353 in Python.
- **348 exact matches** — name and wire ID are identical.
- **0 ID mismatches** — every shared parameter has the same numeric ID.

**Only in Android app (1)**:
- `SYSTEM_BIKE_ERRORS_CODE` (id=265) — **new parameter, should be added to Python**

**Only in Python library (5)**:
- `SYSTEM_GET_NEW_VI` (300) — identification-sequence sentinel, not a real
  parameter in the app enum. Correct to keep in Python as a special value.
- `JUMP_FLOW` (127), `LOCK_HW` (136), `MOTOR_ACCELERATION_RESPONSE` (139),
  `MOTOR_CADENCE_CONTROL` (149) — may have been renamed or removed in app v1.66.
  The Python library may have been extracted from an older app version. These IDs
  are still valid on the wire even if the app no longer names them.

### 2. GATT UUIDs

**TURBOHMI base (TCX)**: `000000xx-3731-3032-494d-484f42525554` — confirmed in
both `BluetoothManager.java` and native library strings.

**GIGATRONIK base (TCU1)**: `000000xx-0000-4b49-4e4f-525441474947` — confirmed
in native library strings.

**Service UUIDs confirmed**:
| Short ID | Purpose | TCX UUID | TCU1 UUID |
|----------|---------|----------|-----------|
| 0x0001 | Request/read | ✅ | ✅ |
| 0x0002 | Write/commands | ✅ | ✅ |
| 0x0003 | Notifications | ✅ | ✅ |

**Characteristic UUIDs confirmed**:
| Short ID | Purpose | Status |
|----------|---------|--------|
| 0x0011 | Service 1 identification/query notifications | ✅ Match |
| 0x0012 | Service 2 ride/multi-packet notifications | ✅ Match |
| 0x0013 | Telemetry notifications | ✅ Match |
| 0x0021 | Service 1 write-without-response | ✅ Match |
| 0x0022 | Service 2 write-without-response | ✅ Match |
| 0x0023 | Service 3 write-without-response | ✅ Match |

The high nibble selects the characteristic role (`0x1S` notify, `0x2S`
write-without-response) and the low nibble identifies service `S`.

### TCX transaction model

The official app does not issue GATT reads for TCX bikes. Its sequence is:

1. Enable service 1 notifications on `0x0011`.
2. CRC-frame the 2-byte parameter ID and write the 20-byte request without
   response to `0x0021`.
3. Match the response notification on `0x0011` by its echoed parameter ID.
4. After identification, enable service 3 and service 2 notifications.
5. Write `SYSTEM_REAL_TIME_DATA_ENB=true` (`01 5a 01`, framed) without response
   to service 3 characteristic `0x0023`.

This is independently visible in the issue #9 HCI capture: zero ATT Read
Requests, 52 Write Commands, and 1010 Handle Value Notifications.

**Additional note**: The Android app scans for standard Cycling Speed & Cadence
service UUID `0x1816`, which the Python library does not reference. This is used
by TCU1 bikes.

### 3. BLE Advertisement Detection

Company IDs and TURBOHMI magic are handled in native code. The Android app:
- Passes raw manufacturer data to `CoreJni.getBikeInfo()` (native)
- Filters scan results by service UUIDs
- Filters device name with regex `^(?>SPECIALIZED\s?...)`

The Python library checks `ADVERTISING_MAGIC = b"TURBOHMI"` in any manufacturer
data payload, and `SIMPLO_COMPANY_ID = 0x020D` for TCU1. This is functionally
equivalent.

### 4. Protocol Generation Detection

**Android `BikeType.java`** defines 13 bike types:
| Types 0–4 | → TCX1 (legacy/TCU1) |
| Types 5–12 | → TCX2 |

At runtime, the app uses `isTCX2ServiceStructure()` — checking if SERVICE_2 has
more than 1 GATT characteristic — to distinguish TCX1 from TCX2 protocol.

The Python library's `BLEProfile` enum (`TCU1`/`TCX`) matches this binary
distinction. The docs' mention of TCX2/TCX3/TCX4 as separate generations is
about parameter support, not wire format — confirmed by the app treating them
all as "TCX2".

### 5. CRC-16 Framing

Native `CRC16Calculator::calculateCRC16_CCITT` confirmed in `libturbo-core.so`.
A precomputed `CRC_CCITT_TABLE` is present. The algorithm matches
CRC-16/CCITT-FALSE (polynomial 0x1021, init 0xFFFF).

Python `framing.py` uses `binascii.crc_hqx(data, 0xFFFF)` — the same algorithm.
✅ **Exact match.**

### 6. AES-128-CTR Encryption

- `ProtocolEncryptionMethod` enum: `NONE=0`, `AES_CTR=1` — confirmed.
- Native functions: `encryptPacket()`, `decryptPacket()` in TurboConnectCore.
- Bytes 0–1 (param ID) in clear, bytes 2–19 encrypted.
- Per-session key derived from identification handshake step 4.

Python `encryption.py` implements the same: header preserved, body encrypted
with AES-128-CTR. ✅ **Match.**

### 7. Key Derivation

`BTEncryptionInfo` stores: `hmiSN`, `hmiHW`, `key` (base64 string).
Key derivation pipeline (in native code):
1. Base64 decode the key string → ~48 raw bytes
2. First 16 bytes = intermediate AES key
3. Remaining bytes = AES-CTR encrypted with intermediate key + zero IV
4. Decrypt → ASCII hex string
5. Hex decode → final 16-byte AES key

Python `encryption.py::derive_key()` implements this exact pipeline.
✅ **Confirmed match.**

### 8. Identification Handshake

**Android**: Full state machine in native `IdentificationSequence`. Supports
both new-bike (7 steps) and reconnect (3 steps) sequences. Returns
`IdentificationResult` with bike type, serial, firmware versions.

**Python**: Uses the full 7-step sequence because it does not persist the
official app's known-bike cache. Each step is CRC-framed, written without
response to service 1, and completed by a matching notification. The official
app may use the short 3-step sequence when reconnecting to a cached bike.
✅ **Correct.**

### 9. F8FF NAK Marker

**Correction (v0.5.0)**: An earlier draft of this report described `F8 FF` as
a "system response envelope" that wrapped valid data.  That was wrong.

The native code's `ProtocolSessionTCX2::isNakPacket` checks the first two
bytes for `F8 FF` and treats any matching packet as a **NAK** (rejection
response):

```
f8 ff [echoed_param_id_be: 2B] [reason_code: 1B] [zeros: 13B] [crc16_le: 2B]
```

The Android app has two distinct mechanisms at different layers:
- `isLegacyPacket()` in the Java routing layer checks for `0xF8 0xFE`
- `isNakPacket()` in the native protocol layer checks for `0xF8 0xFF`

**Bug found**: The Python library's `parse_tcx_message` and `_identify_tcx`
were calling `strip_clear_prefix` to peel off the `F8 FF` bytes and then
parsing the next bytes as if they were a parameter ID and value.  That
silently turned every NAK into bogus telemetry — e.g. a NAK for the
battery-charge request returned `SoC = 5%` because reason `0x05` was
parsed as a state-of-charge byte.  Fixed in 0.5.0: `framing.is_nak_packet`
detects the NAK and `ParsedMessage.nak_reason` carries the rejection code
through to callers.

### 10. Field Conversions

All telemetry field conversions (scaling factors, units, byte sizes) live in the
272 MB native `libturbo-core.so`. They are **not visible** in the decompiled Java
code. The native library's `packetReceived()` returns `DecodeResult` with
`SimpleParameterValue` objects containing decoded string values.

The Python library's TCX field conversions (in `parameters.py`) cannot be
independently verified from the app decompilation alone — they would require
Ghidra analysis of the native binary. The conversions are consistent with the
TCU1 reference (Sepp62/LevoEsp32Ble) and with the documented protocol.

---

## Recommendations

### Add to Python library

1. **`SYSTEM_BIKE_ERRORS_CODE` (id=265)** — new BikeParameter found in app
   v1.66 but missing from `parameters.py`.

2. **Standard service `0x1816`** — Cycling Speed & Cadence, used by TCU1 bikes.
   Could be added to advertisement detection as a secondary signal.

### Documentation updates

1. **`docs/protocol.md` BikeType table** — update to reflect the 13 bike types
   found in the app (PROTOTYPE, TURBO, LEVO1, VADO, PLW, LEVO2, COMO2, PLW2,
   APLW2, PLUTO, APLUTO, APLUTOPLUS, PLUTO2) rather than the simplified
   (1,2)→TCU1, (3,4)→TCX2, (5,6)→TCX3, (7,8)→TCX4 mapping.

2. **Clarify F8FF vs F8FE** — document that the Android app uses F8FE as a
   legacy packet routing marker (separate from the F8FF response envelope).

---

## Ghidra Native Binary Analysis

The 272 MB `libturbo-core.so` was analyzed using Ghidra 12.0.4 headless
analyzer. The binary is **not stripped** and contains **DWARF debug info**,
yielding 5,463 exported symbols in the `TurboConnectCore` namespace and
full C++ source file paths.

### Source File Structure (from DWARF)

The native library was built from:
```
turbo-connect-core/src/identification_sequence.cpp
turbo-connect-core/src/encryption_support.cpp
turbo-connect-core/src/crc_calculator.cpp
turbo-connect-core/src/identify.cpp
turbo-connect-core/src/protocol/protocol_identification.cpp
turbo-connect-core/src/protocol/protocol_identification_tcx2.cpp
turbo-connect-core/3rd-party/fitsdk/fitsdk/Sources/FITSDK/fit_crc.cpp
```

### CRC-16/CCITT-FALSE — Binary Verification ✅

Extracted the 256-entry CRC lookup table directly from binary address
`0x15475c` (`CRC16Calculator::CRC_CCITT_TABLE`). Compared all 256 entries
against the computed CRC-16/CCITT-FALSE table (poly=0x1021, init=0xFFFF):

**256/256 entries match — exact CRC-16/CCITT-FALSE implementation confirmed.**

The table's first entries: `0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5...`
match the standard CRC-CCITT-FALSE polynomial.

### isEncryptablePacket — Decompiled ✅

```c
bool ProtocolSession::isEncryptablePacket(vector<uint8_t>* packet) {
    if (packet->begin != packet->end) {
        return *packet->begin != 0x0A;  // NAK byte
    }
    return false;
}
```

**Finding**: The native `isEncryptablePacket` only checks for NAK byte (`0x0A`).
It does **NOT** check for the `F8 FF` prefix here — that check happens elsewhere
in the packet routing logic.

The Python library's `encryption.py::is_encryptable()` checks for both NAK
**and** F8FF prefix, which is a superset of the native check. This is safe —
the Python library is more conservative about what it encrypts.

### isNakPacket — Decompiled ✅

```c
bool ProtocolSessionTCX2::isNakPacket(vector<uint8_t>* packet) {
    uint8_t* begin = packet->begin;
    if (packet->end - begin > 2 && *begin == 0xF8) {
        return begin[1] == 0xFF;
    }
    return false;
}
```

**Critical finding**: `isNakPacket` in TCX2 checks for `F8 FF` prefix (not
`F8 FE` as previously suggested from the Java decompilation). This means:
- `F8 FF` = **NAK rejection marker** in the native protocol layer
- `F8 FE` = legacy packet detection in the Java routing layer

The Python library's `framing.NAK_PREFIX = b"\xf8\xff"` matches.  Prior to
0.5.0, the same constant existed as `CLEAR_PREFIX` and the parse path
mistakenly stripped it as if it were an envelope wrapping valid data.
That bug has been fixed.

### Identification Handshake — Decompiled ✅

**initShortSteps** pushes parameter IDs to the identification sequence:
1. `300` (SYSTEM_GET_NEW_VI)
2. `0x16B` = `363` (SYSTEM_STATE)
3. If TCX3 or TCX4: adds parameter `14` (BATTERY1_FIRMWARE) for encryption key

This confirms the Python library's 3-step short handshake:
```python
steps = [
    BikeParameter.SYSTEM_GET_NEW_VI,  # 300
    BikeParameter.SYSTEM_STATE,  # 363
    BikeParameter.BATTERY1_FIRMWARE,  # 14
]
```

**Note**: The native code conditionally adds step 3 only for TCX3/TCX4. The
Python library always includes it, which is safe — if the bike doesn't support
encryption, the response will be empty and the library falls back to unencrypted.

### Field Decoders — Decompiled ✅

**decodeUInt8**: Reads `packet[2]` (skipping 2-byte param ID), passes to
`decodeSignedInt()` with ParameterInfo scaling.

**decodeUInt16**: Reads bytes starting at `packet[2]`, copies up to
`min(param.length + 2, packet.size)` bytes, then applies scaling.

**decodeFloat**: Same pattern — reads from `packet[2]`, uses `param.length` to
determine byte count, converts to float, then formats as string with the
parameter's scaling.

All decoders skip the first 2 bytes (parameter ID) and read `param.length`
bytes of data. This matches the Python library's approach of extracting data
after the 2-byte parameter ID and applying per-field conversions.

### Key Derivation — Decompiled ✅

**decryptHexString**: The decompiled code shows:
1. `hexStringToByteVector()` — converts hex string inputs to byte vectors
2. Creates `AES_ctx` with zeroed-out round keys (zero IV)
3. Calls AES decryption on the data

This is part of the key derivation pipeline. Combined with the
`BTEncryptionInfo.key` field (base64 string), the full pipeline is:
base64 decode → split at 16 → AES decrypt with zero IV → hex decode.

The Python `encryption.py::derive_key()` implements this exact pipeline. ✅

### Encryption Layout — Decompiled

**encryptPacket** and **decryptPacket**: Both take `(key, iv, packet)` vectors.
The actual implementation is behind an indirect call (vtable/thunk), but the
function signatures confirm: `vector<uint8_t> key`, `vector<uint8_t> iv`,
`vector<uint8_t> packet` → returns `vector<uint8_t>`.

The AES implementation uses `AES_ECB_encrypt` as the primitive (visible in
exported symbols), which is standard for implementing CTR mode on top of ECB.
This confirms AES-128-CTR.

---

## Methodology

- **APK decompilation**: jadx 1.5.5 (via Nix) on `com.specialized.android.apk`
- **Native binary analysis**: Ghidra 12.0.4 headless (via Nix) on
  `libturbo-core.so` (272 MB, ARM64, not stripped, DWARF debug info)
- **Binary table extraction**: Direct read of CRC-16 lookup table from ELF
- **Symbol analysis**: `nm -D` with `c++filt` — 5,463 exported C++ symbols
- **Automated comparison**: Python scripts for BikeParameter enum diffing
- **Source**: `Specialized_1.66.0_APKPure.xapk`
- **Key files examined**:
  - `com.specialized.turboconnect.model.BikeParameter` (352 param IDs)
  - `com.specialized.turboconnect.bluetooth.*` (BLE stack)
  - `com.specialized.turboconnect.jni.*` (JNI bridge to native)
  - `com.specialized.turboconnect.model.BTEncryptionInfo` (key exchange)
  - `com.specialized.turboconnect.model.BikeType` (generation mapping)
  - `com.specialized.turboconnect.model.ProtocolEncryptionMethod` (AES-CTR)
  - `TurboConnectCore::CRC16Calculator` (native CRC implementation)
  - `TurboConnectCore::ProtocolSession::isEncryptablePacket` (encryption bypass)
  - `TurboConnectCore::ProtocolSessionTCX2::isNakPacket` (F8FF detection)
  - `TurboConnectCore::IdentificationSequence::initShortSteps` (handshake)
  - `TurboConnectCore::ParameterInfo::decode*` (field decoders)
