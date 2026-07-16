# specialized-turbo

Python library for talking to Specialized Turbo e-bikes (Vado, Levo, Creo) over Bluetooth Low Energy. Reads speed, power, cadence, battery, motor temp, odometer, assist level, range. Can also write settings like assist level and acceleration.

Async, built on [bleak](https://github.com/hbldh/bleak). Includes a CLI. Protocol docs in [docs/protocol.md](docs/protocol.md).

## Installation

```bash
pip install specialized-turbo
```

Every command (`scan`, `telemetry`, `read`, `write`, `capture`, `services`)
works out of the box; there are no optional extras.

## Quick start

> **TCX2+ bikes (Vado/Levo/Creo SL, etc.) require identification.** Pass the
> parsed advertisement (`bike_info`, from `parse_bike_info`) and the bike's
> AES key (`key`, a `BikeEncryptionKey`) so the connection can run the
> encrypted identification handshake and negotiate the protocol revision.
> This library has no account/login or network key-fetching feature of any
> kind: the key can never be obtained over BLE, and must be supplied by the
> caller from an external, authorized source (see *Encryption keys* below).
> TCU1 bikes (2018 Levo) need neither — just the address and PIN.

### Stream telemetry (TCX2+)

```python
import asyncio
from specialized_turbo import SpecializedConnection, TelemetryMonitor
from specialized_turbo import parse_bike_info, BikeEncryptionKey

async def main():
    # bike_info comes from the BLE advertisement; key from an external,
    # authorized source.
    async with SpecializedConnection(
        "DC:DD:BB:4A:D6:55", pin="946166", bike_info=info, key=key
    ) as conn:
        monitor = TelemetryMonitor(conn)
        await monitor.start()

        async for msg in monitor.stream():
            print(f"{msg.field_name} = {msg.converted_value} {msg.unit}")

asyncio.run(main())
```

### Read the snapshot

```python
async with SpecializedConnection(
    "DC:DD:BB:4A:D6:55", pin="946166", bike_info=info, key=key
) as conn:
    monitor = TelemetryMonitor(conn)
    await monitor.start()
    await asyncio.sleep(5)

    snap = monitor.snapshot
    print(f"Speed: {snap.motor.speed_kmh} km/h")
    print(f"Battery: {snap.battery.charge_pct}%")
    print(f"Power: {snap.motor.rider_power_w} W (rider) + {snap.motor.motor_power_w} W (motor)")
    print(f"Cadence: {snap.motor.cadence_rpm} RPM")
    print(f"Assist: {snap.motor.assist_level}")
```

### Query a single value (TCU1)

```python
from specialized_turbo import SpecializedConnection, Sender, BatteryChannel
from specialized_turbo import BLEProfile

async with SpecializedConnection(
    "DC:DD:BB:4A:D6:55", pin="946166", generation=BLEProfile.TCU1
) as conn:
    msg = await conn.request_value(Sender.BATTERY, BatteryChannel.CHARGE_PERCENT)
    print(f"Battery: {msg.converted_value}%")
```

### Write commands

```python
async with SpecializedConnection(
    "DC:DD:BB:4A:D6:55", pin="946166", bike_info=info, key=key
) as conn:
    await conn.set_assist_level(2)          # TRAIL
    await conn.set_acceleration(50.0)       # 50%
    await conn.set_assist_percentage(0, 35) # ECO = 35%
    # set_shuttle(...) is TCU1-only: no verified TCX2+ equivalent.
```

## CLI

Every command that connects to a specific bike (`telemetry`, `read`, `write`,
`capture`) first resolves the bike's advertisement (`scan`-style, filtered by
address) into a `BikeInfo`. TCU1 bikes need no key. TCX2+ bikes need their
AES-128 key, supplied via:

- `--key-file FILE`: a self-describing, versioned JSON key file (see
  *Encryption keys* below), validated against the bike's HMI hardware/serial
  IDs.

There is no inline `--key` flag, no environment variable, and no
account/login or network key-fetching feature of any kind: this library
cannot obtain a TCX2+ key for you. The key can never be read over BLE --
it must come from an external, authorized source and be placed in a key
file yourself before running any TCX2+ command.

Scan for bikes (prints a safe `BikeInfo` summary -- never any key/credential material):

```bash
specialized-turbo scan
specialized-turbo scan --timeout 15
```

### Encryption keys (key-file format)

A key file is a small JSON object, self-describing and bound to one
specific bike by its HMI hardware/serial IDs:

```json
{
  "version": 1,
  "hmi_hw": "B.4.3",
  "hmi_sn": "1234",
  "key": "00112233445566778899aabbccddeeff"
}
```

- `version`: format version; currently always `1`.
- `hmi_hw` / `hmi_sn`: the bike's HMI hardware version and serial number, as
  reported in its BLE advertisement (see `specialized-turbo scan`). A key
  file whose `hmi_hw`/`hmi_sn` don't match the resolved bike is refused.
- `key`: the derived 16-byte AES-128 key, as a 32-character lowercase hex
  string.

**Sensitivity:** the file contains secret key material -- treat it like a
credential (restrict its permissions, don't commit it to version control,
don't share it). Reading a key file is bounded to a small size limit and
warns on stderr if its permissions are more permissive than `0600` on
POSIX. On Windows there is no `os`-level equivalent of POSIX file-mode
bits; restrict access to the file yourself (e.g. via NTFS ACLs) if that
matters for your threat model -- this library cannot check or enforce
file permissions on Windows.

**Acquiring a key:** this library has no built-in, normal-user way to
acquire a TCX2+ bike's key -- there is no account/login flow, and the key
is never available over BLE. You must obtain the key yourself from an
external, authorized source and write the key file above by hand (or with
your own tooling) before using `--key-file`.

Stream telemetry:

```bash
specialized-turbo telemetry DC:DD:BB:4A:D6:55 --pin 946166 --key-file vado.key.json
specialized-turbo telemetry DC:DD:BB:4A:D6:55 --pin 946166 --key-file vado.key.json --format json
specialized-turbo telemetry DC:DD:BB:4A:D6:55 --pin 946166 --key-file vado.key.json --duration 30

# TCU1 (2018 Levo) bikes need no key at all:
specialized-turbo telemetry DC:DD:BB:4A:D6:55 --pin 946166
```

Read a single value:

```bash
specialized-turbo read list                                             # show available fields
specialized-turbo read battery_charge_percent DC:DD:BB:4A:D6:55 --pin 946166           # TCU1
specialized-turbo read speed DC:DD:BB:4A:D6:55 --pin 946166 --key-file vado.key.json   # TCX2+
```

Write a value:

```bash
specialized-turbo write list                                            # show writable fields
specialized-turbo write assist_level 2 DC:DD:BB:4A:D6:55 --pin 946166  # TCU1: set to TRAIL
specialized-turbo write assist_level 2 DC:DD:BB:4A:D6:55 --pin 946166 --key-file vado.key.json  # TCX2+
```

Dump GATT services (debugging):

```bash
specialized-turbo services DC:DD:BB:4A:D6:55 --pin 946166
```

Capture complete TCX writes and notifications for protocol debugging:

```bash
specialized-turbo capture DC:DD:BB:4A:D6:55 --duration 60 --key-file vado.key.json > tcx-capture.tsv
```

## Available fields

| Field | Unit | Writable | Description |
| --- | --- | --- | --- |
| `battery_capacity_wh` | Wh | | Total battery capacity |
| `battery_remaining_wh` | Wh | | Remaining energy |
| `battery_health` | % | | Battery health |
| `battery_temp` | °C | | Battery temperature |
| `battery_charge_cycles` | cycles | | Number of charge cycles |
| `battery_voltage` | V | | Battery voltage |
| `battery_current` | A | | Battery current draw |
| `battery_charge_percent` | % | | State of charge |
| `rider_power` | W | | Rider pedal power |
| `cadence` | RPM | | Pedaling cadence |
| `speed` | km/h | | Current speed |
| `odometer` | km | | Total distance |
| `assist_level` | -- | yes | OFF / ECO / TRAIL / TURBO |
| `motor_temp` | °C | | Motor temperature |
| `motor_power` | W | | Electric motor power |
| `peak_assist` | % | | ECO / TRAIL / TURBO percentages |
| `shuttle` | -- | yes | Shuttle mode value (0-100) |
| `wheel_circumference` | mm | yes | Wheel circumference setting |
| `assist_lev1_pct` | % | yes | ECO assist percentage |
| `assist_lev2_pct` | % | yes | TRAIL assist percentage |
| `assist_lev3_pct` | % | yes | TURBO assist percentage |
| `fake_channel` | -- | | Bit-coded internal channel |
| `acceleration` | % | yes | Acceleration sensitivity |

TCX2+ bikes have additional fields (range, altitude, gradient, calories, system temperature, and more). See [docs/protocol.md](docs/protocol.md) for the full list.

## Protocol support

Four protocol generations exist:

| Protocol | Message format | Encryption |
| --- | --- | --- |
| TCU1 | `[sender][channel][data]` | None |
| TCX2 | 2-byte parameter ID + CRC-16 | Optional AES-128-CTR |
| TCX3 | Same as TCX2 | Optional AES-128-CTR |
| TCX4 | Same as TCX2 | Optional AES-128-CTR |

TCX2/3/4 share one wire format and differ only in which parameters the bike supports. The `BLEProfile` enum (`TCU1` / `TCX`) controls which GATT UUIDs to use.

See [docs/protocol.md](docs/protocol.md) for the full spec.

## Pairing

The bike needs a 6-digit PIN for BLE pairing, shown on its TCU screen. Pass it via `--pin` (CLI) or `pin=` (Python).

On Windows, bleak's WinRT backend can handle passkey pairing programmatically. If that doesn't work, pair through Windows Bluetooth Settings first, then connect without `--pin`.

Some newer bikes use numeric comparison instead of passkey entry. On those, pair through your OS Bluetooth settings first.

## Development

```bash
uv sync --extra dev
uv run pytest
```

## License

MIT
