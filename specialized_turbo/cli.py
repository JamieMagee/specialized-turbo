"""
Command-line interface for the Specialized Turbo Vado BLE library.

Provides subcommands for scanning, connecting, and reading telemetry.

Uses ``argparse`` (no extra dependencies) with optional ``click`` upgrade path.

Encryption keys (TCX2+ bikes)
------------------------------
A TCX2+ bike needs its AES-128 key to complete the identification
handshake. This CLI never accepts a key inline (no ``--key`` flag, no
environment variable) and has no account/login or network key-fetching
feature of any kind. The key can never be obtained over BLE -- it must
come from an external, authorized source and be supplied via
``--key-file FILE``: a self-describing, versioned JSON key file bound to
the bike's HMI hardware/serial IDs (see the ``--key-file`` help text for
the exact format).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import stat
import sys
import time

from bleak.backends.characteristic import BleakGATTCharacteristic

from .bike_info import BikeInfo, parse_bike_info
from .connection import (
    find_advertisement_by_address,
    scan_for_bikes,
    SpecializedConnection,
)
from .identification import IdentificationError
from .keystore.exceptions import InvalidEncryptionKeyError
from .keystore.models import BikeEncryptionKey
from .parameters import all_tcx_fields
from .protocol import (
    all_field_defs,
    BLEProfile,
)
from .telemetry import run_telemetry_session
from .transport import BLETraceEvent


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# CLI-level errors
# ---------------------------------------------------------------------------


class BikeNotFoundError(Exception):
    """No advertisement was seen from the requested address within the scan timeout."""


class BikeInfoIncompleteError(Exception):
    """The device was detected but its advertisement could not be fully decoded.

    Typically an Apple-iBeacon-only or name-only detection with no Nordic
    10-byte structured record -- the HMI hardware/serial IDs (needed for
    identification and key binding) aren't derivable from it.
    """


class KeyRequiredError(Exception):
    """A TCX2+ command needs a key but --key-file was not given."""


class KeyFileError(Exception):
    """Raised for any problem reading or validating a key file."""


_CLI_ERRORS: tuple[type[Exception], ...] = (
    BikeNotFoundError,
    BikeInfoIncompleteError,
    KeyRequiredError,
    KeyFileError,
)


# ---------------------------------------------------------------------------
# Bike discovery / identification resolution
# ---------------------------------------------------------------------------


async def _resolve_bike_info(address: str, timeout: float) -> BikeInfo:
    """Resolve the ``BikeInfo`` for *address* via a fresh, address-filtered scan.

    Shared by every command that connects to a specific bike (``telemetry``,
    ``read``, ``write``, ``capture``). TCU1 bikes are always
    ``complete`` (see :func:`~specialized_turbo.bike_info.parse_bike_info`)
    and never need a key. A TCX bike whose advertisement can't be fully
    decoded (e.g. only the Apple iBeacon detection magic was seen, not the
    structured Nordic record) raises :class:`BikeInfoIncompleteError` rather
    than proceeding with unknown HMI hardware/serial IDs.
    """
    found = await find_advertisement_by_address(address, timeout=timeout)
    if found is None:
        raise BikeNotFoundError(
            f"No advertisement received from {address} within {timeout:g}s. "
            "Make sure the bike is powered on, awake, and within BLE range, "
            "then try again."
        )
    device, adv = found
    info = parse_bike_info(device.name or "", adv.manufacturer_data)

    if info.ble_profile == BLEProfile.TCU1:
        return info

    if not info.is_bike:
        raise BikeInfoIncompleteError(
            f"The device at {address} does not look like a Specialized "
            "Turbo bike (no recognized advertisement data)."
        )

    if not info.complete:
        raise BikeInfoIncompleteError(
            f"Advertisement from {address} was detected as a Specialized "
            "bike but could not be fully decoded (only Apple iBeacon / "
            "name-only detection magic was seen, not the full Nordic "
            "advertisement record). Move closer to the bike and retry."
        )

    return info


# ---------------------------------------------------------------------------
# Key file (self-describing, versioned JSON; bound to hmi_hw + hmi_sn)
# ---------------------------------------------------------------------------
#
# Key files are produced out-of-band by an external, authorized source
# (this library provides no account/login or network key-fetching feature
# of any kind -- the key can never be obtained over BLE). The expected
# JSON schema is a flat object::
#
#     {
#         "version": 1,
#         "hmi_hw": "<HMI hardware version string, e.g. \"B.4.3\">",
#         "hmi_sn": "<HMI serial number string>",
#         "key": "<32-character lowercase hex string; the derived 16-byte AES key>"
#     }
#
# ``hmi_hw``/``hmi_sn`` bind the file to one specific bike -- a key file
# for a different bike is refused (see :func:`_read_key_file`). The file
# contains secret key material: treat it like a credential (restrict its
# permissions, keep it out of version control/backups you don't control).

_KEY_FILE_VERSION = 1
_KEY_HEX_RE = re.compile(r"[0-9a-f]{32}")
#: A genuine key file (version + hmi_hw + hmi_sn + 32-char hex key, as
#: JSON) is well under 200 bytes; 4 KiB is a generous ceiling that still
#: bounds memory use and rejects anything absurdly oversized outright.
_MAX_KEY_FILE_BYTES = 4096


def _warn_if_permissive(path: str) -> None:
    """Warn (stderr) if *path* is readable/writable by group or other.

    POSIX only -- Windows has no equivalent st_mode permission bits via
    ``os.stat``, so this is a no-op there. On Windows, restrict access to
    the key file yourself (e.g. via NTFS ACLs) if that matters for your
    threat model; this CLI cannot check or enforce that for you.
    """
    if os.name != "posix":
        return
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return
    if mode & 0o077:
        print(
            f"Warning: {path} is readable by group/other (mode "
            f"{oct(mode)}). Consider tightening it: chmod 600 {path}",
            file=sys.stderr,
        )


def _read_key_file(path: str, bike_info: BikeInfo) -> BikeEncryptionKey:
    """Read, validate, and return the key from a self-describing key file.

    Validates the file's format version and that its ``hmi_hw``/``hmi_sn``
    binding matches *bike_info* -- a key file for a different bike is
    refused rather than silently used. Never logs or prints the raw key.

    The read is bounded to :data:`_MAX_KEY_FILE_BYTES` (a genuine key file
    is well under 200 bytes): an oversized file is rejected outright,
    without ever loading more than that bound into memory or echoing any
    of its content in the error.
    """
    try:
        with open(path, "rb") as fh:
            raw_bytes = fh.read(_MAX_KEY_FILE_BYTES + 1)
    except FileNotFoundError:
        raise KeyFileError(f"Key file not found: {path}") from None
    except OSError as exc:
        raise KeyFileError(f"Could not read key file {path}: {exc}") from None

    if len(raw_bytes) > _MAX_KEY_FILE_BYTES:
        raise KeyFileError(
            f"Key file {path} exceeds the {_MAX_KEY_FILE_BYTES}-byte limit "
            "for a key file; refusing to read it"
        )

    _warn_if_permissive(path)

    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise KeyFileError(f"Key file {path} is not valid UTF-8 ({exc})") from None

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise KeyFileError(f"Key file {path} is not valid JSON: {exc}") from None

    if not isinstance(payload, dict):
        raise KeyFileError(f"Key file {path} must contain a JSON object")

    version = payload.get("version")
    if version != _KEY_FILE_VERSION:
        raise KeyFileError(
            f"Key file {path} has unsupported version {version!r} "
            f"(expected {_KEY_FILE_VERSION})"
        )

    file_hw = payload.get("hmi_hw")
    file_sn = payload.get("hmi_sn")
    raw_hex = payload.get("key")
    if (
        not isinstance(file_hw, str)
        or not isinstance(file_sn, str)
        or not isinstance(raw_hex, str)
    ):
        raise KeyFileError(f"Key file {path} is missing required fields")

    if bike_info.hmi_hardware_version != file_hw or bike_info.hmi_serial != file_sn:
        raise KeyFileError(
            f"Key file {path} is bound to hmi_hw={file_hw!r} "
            f"hmi_sn={file_sn!r}, but the resolved bike identifies as "
            f"hmi_hw={bike_info.hmi_hardware_version!r} "
            f"hmi_sn={bike_info.hmi_serial!r}. Refusing to use a key file "
            "for the wrong bike."
        )

    if not _KEY_HEX_RE.fullmatch(raw_hex):
        raise KeyFileError(
            f"Key file {path} does not contain a 32-character lowercase hex key"
        )

    try:
        return BikeEncryptionKey(raw=raw_hex)
    except InvalidEncryptionKeyError as exc:
        raise KeyFileError(f"Key file {path} contains an invalid key ({exc})") from None


async def _resolve_key(
    bike_info: BikeInfo, args: argparse.Namespace
) -> BikeEncryptionKey | None:
    """Resolve the encryption key (if any) needed to connect to *bike_info*.

    TCU1 bikes bypass key resolution entirely (``None``). A TCX bike needs
    ``--key-file`` (read + HMI-bound validated); if it's not given, raises
    :class:`KeyRequiredError`. This key can never be obtained over BLE --
    it must come from an external, authorized source.
    """
    if bike_info.ble_profile == BLEProfile.TCU1:
        return None

    key_file = getattr(args, "key_file", None)

    if key_file is not None:
        return _read_key_file(key_file, bike_info)

    raise KeyRequiredError(
        "This bike requires an encryption key: pass --key-file FILE. This "
        "key can never be obtained over BLE; it must come from an "
        "external, authorized source."
    )


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


async def _cmd_scan(args: argparse.Namespace) -> None:
    """Scan for nearby Specialized Turbo bikes."""
    print(f"Scanning for Specialized bikes ({args.timeout}s) ...")
    results = await scan_for_bikes(timeout=args.timeout)

    if not results:
        print("No Specialized bikes found.")
        print("Make sure the bike is powered on and Bluetooth is enabled.")
        return

    print(f"\nFound {len(results)} bike(s):\n")
    for device, adv in results:
        # BikeInfo never carries key/credential material, so this summary
        # is always safe to print in full.
        info = parse_bike_info(device.name or "", adv.manufacturer_data)
        print(f"  Name:      {device.name or '(unknown)'}")
        print(f"  Address:   {device.address}")
        print(f"  RSSI:      {adv.rssi} dBm")
        print(f"  Bike:      {info.bike_name}")
        print(
            f"  Profile:   {info.ble_profile.name if info.ble_profile else 'unknown'}"
        )
        print(f"  Complete:  {info.complete}")
        if info.complete:
            print(f"  HMI type:  {info.hmi_type.name if info.hmi_type else 'unknown'}")
            print(f"  HMI HW:    {info.hmi_hardware_version}")
            print(f"  HMI serial:{info.hmi_serial}")
            if info.bike_type is not None:
                print(f"  Bike type: {info.bike_type.name}")
            if info.system_state is not None:
                print(f"  State:     {info.system_state.name}")
        print()


# ---------------------------------------------------------------------------
# telemetry
# ---------------------------------------------------------------------------


async def _cmd_telemetry(args: argparse.Namespace) -> None:
    """Connect and stream live telemetry."""
    print(f"Resolving {args.address} ...")
    bike_info = await _resolve_bike_info(args.address, args.scan_timeout)
    generation = bike_info.ble_profile or BLEProfile.TCX
    key = await _resolve_key(bike_info, args)

    print(f"Connecting to {args.address} ...")
    snapshot = await run_telemetry_session(
        args.address,
        pin=args.pin,
        generation=generation,
        bike_info=bike_info,
        key=key,
        duration=args.duration,
        output_format=args.format,
    )

    # Print final summary
    print("\n--- Session Summary ---")
    d = snapshot.as_dict()
    if args.format == "json":
        print(json.dumps(d, indent=2, default=str))
    else:
        for section, values in d.items():
            if isinstance(values, dict):
                print(f"\n  {section}:")
                for k, v in values.items():
                    print(f"    {k:<28s} = {v}")
            else:
                print(f"  {section}: {values}")


# ---------------------------------------------------------------------------
# read
# ---------------------------------------------------------------------------

# Map human-readable names → (sender, channel)
_FIELD_NAME_MAP: dict[str, tuple[int, int]] = {}
for _key, _fd in all_field_defs().items():
    _FIELD_NAME_MAP[_fd.name] = _key

# Map human-readable names → TCX parameter ID
_TCX_FIELD_NAME_MAP: dict[str, int] = {}
for _param_id, _tfd in all_tcx_fields().items():
    _TCX_FIELD_NAME_MAP[_tfd.name] = _param_id

# Writable TCX fields: name → param id
_TCX_WRITABLE_FIELD_MAP: dict[str, int] = {
    name: param_id
    for name, param_id in _TCX_FIELD_NAME_MAP.items()
    if all_tcx_fields()[param_id].writable
}


async def _cmd_read(args: argparse.Namespace) -> None:
    """Connect, read a specific value, and disconnect."""
    field_name = args.field

    if field_name == "list":
        print("Available fields:\n")
        print("  TCU1 fields:")
        for name, (sender, channel) in sorted(_FIELD_NAME_MAP.items()):
            fd = all_field_defs()[(sender, channel)]
            print(
                f"    {name:<28s}  (sender=0x{sender:02x} channel=0x{channel:02x})  [{fd.unit}]"
            )
        print("\n  TCX fields:")
        for name, param_id in sorted(_TCX_FIELD_NAME_MAP.items()):
            tfd = all_tcx_fields()[param_id]
            print(f"    {name:<28s}  (param={param_id})  [{tfd.unit}]")
        return

    # Prefer TCX field lookup, fall back to TCU1
    tcx_param_id = _TCX_FIELD_NAME_MAP.get(field_name)
    tcu1_key = _FIELD_NAME_MAP.get(field_name)

    if tcx_param_id is None and tcu1_key is None:
        print(f"Unknown field: {field_name}")
        print("Use 'read list' to see available fields.")
        sys.exit(1)

    print(f"Resolving {args.address} ...")
    bike_info = await _resolve_bike_info(args.address, args.scan_timeout)

    if tcx_param_id is not None and bike_info.ble_profile == BLEProfile.TCX:
        tfd = all_tcx_fields()[tcx_param_id]
        key = await _resolve_key(bike_info, args)
        print(f"Connecting to {args.address} to read '{field_name}' ...")
        async with SpecializedConnection(
            args.address,
            pin=args.pin,
            generation=BLEProfile.TCX,
            bike_info=bike_info,
            key=key,
        ) as conn:
            msg = await conn.request_tcx_parameter(tfd.param)
            if msg.nak_reason is not None:
                if args.format == "json":
                    print(
                        json.dumps(
                            {
                                "field": field_name,
                                "rejected": True,
                                "reason": msg.nak_reason,
                            },
                            default=str,
                        )
                    )
                else:
                    print(
                        f"{field_name}: rejected by bike (reason 0x{msg.nak_reason:02x})"
                    )
            else:
                converted = tfd.convert(msg.value) if msg.value is not None else None
                if args.format == "json":
                    print(
                        json.dumps(
                            {
                                "field": field_name,
                                "value": converted,
                                "raw": msg.value,
                                "unit": tfd.unit,
                            },
                            default=str,
                        )
                    )
                else:
                    print(f"{field_name} = {converted} {tfd.unit}")
        return

    if tcu1_key is not None and bike_info.ble_profile == BLEProfile.TCU1:
        sender, channel = tcu1_key
        print(f"Connecting to {args.address} to read '{field_name}' ...")

        async with SpecializedConnection(
            args.address, pin=args.pin, generation=BLEProfile.TCU1
        ) as conn:
            msg = await conn.request_value(sender, channel)
            if args.format == "json":
                if msg.nak_reason is not None:
                    print(
                        json.dumps(
                            {
                                "field": field_name,
                                "rejected": True,
                                "reason": msg.nak_reason,
                            },
                            default=str,
                        )
                    )
                else:
                    print(
                        json.dumps(
                            {
                                "field": msg.field_name,
                                "value": msg.converted_value,
                                "raw": msg.raw_value,
                                "unit": msg.unit,
                            },
                            default=str,
                        )
                    )
            else:
                if msg.nak_reason is not None:
                    print(
                        f"{field_name}: rejected by bike (reason 0x{msg.nak_reason:02x})"
                    )
                else:
                    print(f"{msg.field_name} = {msg.converted_value} {msg.unit}")
        return

    print(
        f"Field '{field_name}' is not available on this bike's protocol "
        f"({bike_info.ble_profile.name if bike_info.ble_profile else 'unknown'})."
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------

# Writable fields: name → (sender, channel, FieldDefinition)
_WRITABLE_FIELD_MAP: dict[str, tuple[int, int]] = {}
for _key, _fd in all_field_defs().items():
    if _fd.writable:
        _WRITABLE_FIELD_MAP[_fd.name] = _key


async def _cmd_write(args: argparse.Namespace) -> None:
    """Connect, write a value, and disconnect."""
    field_name = args.field

    if field_name == "list":
        print("Writable fields:\n")
        print("  TCU1 fields:")
        for name, (sender, channel) in sorted(_WRITABLE_FIELD_MAP.items()):
            fd = all_field_defs()[(sender, channel)]
            print(
                f"    {name:<28s}  (sender=0x{sender:02x} channel=0x{channel:02x})  [{fd.unit}]"
            )
        print("\n  TCX fields:")
        for name, param_id in sorted(_TCX_WRITABLE_FIELD_MAP.items()):
            tfd = all_tcx_fields()[param_id]
            print(f"    {name:<28s}  (param={param_id})  [{tfd.unit}]")
        return

    tcx_param_id = _TCX_WRITABLE_FIELD_MAP.get(field_name)
    tcu1_key = _WRITABLE_FIELD_MAP.get(field_name)

    if tcx_param_id is None and tcu1_key is None:
        print(f"Unknown or read-only field: {field_name}")
        print("Use 'write list' to see writable fields.")
        sys.exit(1)

    if args.value is None or args.address is None:
        print("Usage: specialized-turbo write <field> <value> <address>")
        sys.exit(1)

    print(f"Resolving {args.address} ...")
    bike_info = await _resolve_bike_info(args.address, args.scan_timeout)

    if tcx_param_id is not None and bike_info.ble_profile == BLEProfile.TCX:
        tfd = all_tcx_fields()[tcx_param_id]
        raw_value = float(args.value) if "." in args.value else int(args.value)
        wire_value = tfd.encode(raw_value) if tfd.encode is not None else int(raw_value)
        data_bytes = wire_value.to_bytes(tfd.data_size, "little")

        key = await _resolve_key(bike_info, args)
        print(f"Connecting to {args.address} to write '{field_name}' = {raw_value} ...")
        async with SpecializedConnection(
            args.address,
            pin=args.pin,
            generation=BLEProfile.TCX,
            bike_info=bike_info,
            key=key,
        ) as conn:
            await conn.write_tcx_parameter(tfd.param, data_bytes)
            print(
                f"Wrote {field_name} = {raw_value} (raw: {wire_value}, "
                f"bytes: {data_bytes.hex()})"
            )
        return

    if tcu1_key is not None and bike_info.ble_profile == BLEProfile.TCU1:
        sender, channel = tcu1_key
        fd = all_field_defs()[(sender, channel)]

        raw_value = float(args.value) if "." in args.value else int(args.value)
        wire_value = fd.encode(raw_value) if fd.encode is not None else int(raw_value)

        from .protocol import build_write_command

        data_bytes = wire_value.to_bytes(fd.data_size, "little")
        command = build_write_command(sender, channel, data_bytes)

        print(f"Connecting to {args.address} to write '{field_name}' = {raw_value} ...")

        async with SpecializedConnection(
            args.address, pin=args.pin, generation=BLEProfile.TCU1
        ) as conn:
            await conn.write_command(command)
            print(
                f"Wrote {field_name} = {raw_value} (raw: {wire_value}, "
                f"bytes: {command.hex()})"
            )
        return

    print(
        f"Field '{field_name}' is not available on this bike's protocol "
        f"({bike_info.ble_profile.name if bike_info.ble_profile else 'unknown'})."
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# services (debug helper)
# ---------------------------------------------------------------------------


async def _cmd_services(args: argparse.Namespace) -> None:
    """Connect and enumerate all GATT services/characteristics (debug)."""
    from bleak import BleakClient

    print(f"Connecting to {args.address} ...")
    async with BleakClient(args.address) as client:
        if args.pin is not None:
            try:
                await client.pair(protection_level=2)
            except Exception as e:
                print(f"Pairing note: {e}")

        print("Connected. Enumerating services ...\n")
        for service in client.services:
            print(f"Service: {service.uuid}  [{service.description}]")
            for char in service.characteristics:
                props = ", ".join(char.properties)
                print(f"  Char: {char.uuid}  [{props}]  {char.description}")
                for desc in char.descriptors:
                    print(f"    Desc: {desc.uuid}  {desc.description}")
            print()


# ---------------------------------------------------------------------------
# capture (debug helper)
# ---------------------------------------------------------------------------


async def _cmd_capture(args: argparse.Namespace) -> None:
    """Capture complete TCX writes and notifications as tab-separated hex."""
    print(f"Resolving {args.address} ...")
    bike_info = await _resolve_bike_info(args.address, args.scan_timeout)
    generation = bike_info.ble_profile or BLEProfile.TCX
    key = await _resolve_key(bike_info, args)

    started = time.monotonic()

    def trace(event: BLETraceEvent) -> None:
        elapsed = event.timestamp - started
        print(
            f"{elapsed:.6f}\t{event.direction.upper()}\t"
            f"{int(event.service_id)}\t{event.characteristic}\t{event.data.hex()}",
            flush=True,
        )

    def discard(
        _sender: BleakGATTCharacteristic,
        _data: bytearray,
    ) -> None:
        pass

    print("seconds\tdirection\tservice\tcharacteristic\tpayload", flush=True)
    async with SpecializedConnection(
        args.address,
        pin=args.pin,
        generation=generation,
        bike_info=bike_info,
        key=key,
        trace_callback=trace,
    ) as conn:
        await conn.subscribe_notifications(discard)
        try:
            if args.duration > 0:
                await asyncio.sleep(args.duration)
            else:
                await asyncio.Event().wait()
        finally:
            await conn.unsubscribe_notifications()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def _add_key_args(parser: argparse.ArgumentParser) -> None:
    """Add the --key-file/--scan-timeout options shared by every command
    that connects to a specific bike.

    No inline key argument and no environment variable are ever accepted,
    and this CLI has no account/login or network key-fetching feature of
    any kind -- the key can never be obtained over BLE. It must be
    supplied via a key file (validated against the bike's HMI binding),
    produced out-of-band from an external, authorized source.
    """
    parser.add_argument(
        "--key-file",
        type=str,
        default=None,
        help=(
            "Path to a versioned JSON key file bound to the bike's HMI "
            "hardware/serial IDs (TCX2+ only). Obtain this from an "
            "external, authorized source -- it can never be fetched over "
            "BLE."
        ),
    )
    parser.add_argument(
        "--scan-timeout",
        type=float,
        default=10.0,
        help="Timeout (seconds) for resolving the bike's advertisement",
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="specialized-turbo",
        description="Interact with Specialized Turbo e-bikes over Bluetooth LE",
        allow_abbrev=False,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    # --- scan ---
    p_scan = sub.add_parser(
        "scan", help="Scan for nearby Specialized bikes", allow_abbrev=False
    )
    p_scan.add_argument(
        "-t", "--timeout", type=float, default=10.0, help="Scan duration (seconds)"
    )

    # --- telemetry ---
    p_tel = sub.add_parser(
        "telemetry", help="Stream live telemetry", allow_abbrev=False
    )
    p_tel.add_argument("address", help="BLE MAC address (e.g. DC:DD:BB:4A:D6:55)")
    p_tel.add_argument("-p", "--pin", type=str, default=None, help="Pairing PIN")
    p_tel.add_argument(
        "-d",
        "--duration",
        type=float,
        default=0,
        help="Duration in seconds (0=forever)",
    )
    p_tel.add_argument("-f", "--format", choices=["table", "json"], default="table")
    _add_key_args(p_tel)

    # --- read ---
    p_read = sub.add_parser(
        "read",
        help="Read a specific value (use 'read list' to see fields)",
        allow_abbrev=False,
    )
    p_read.add_argument("field", help="Field name or 'list'")
    p_read.add_argument("address", nargs="?", default=None, help="BLE MAC address")
    p_read.add_argument("-p", "--pin", type=str, default=None, help="Pairing PIN")
    p_read.add_argument("-f", "--format", choices=["table", "json"], default="table")
    _add_key_args(p_read)

    # --- services ---
    p_svc = sub.add_parser(
        "services", help="Enumerate GATT services (debug)", allow_abbrev=False
    )
    p_svc.add_argument("address", help="BLE MAC address")
    p_svc.add_argument("-p", "--pin", type=str, default=None, help="Pairing PIN")

    # --- capture ---
    p_capture = sub.add_parser(
        "capture",
        help="Capture raw TCX writes and notifications",
        allow_abbrev=False,
    )
    p_capture.add_argument("address", help="BLE MAC address")
    p_capture.add_argument("-p", "--pin", type=str, default=None, help="Pairing PIN")
    p_capture.add_argument(
        "-d",
        "--duration",
        type=float,
        default=60,
        help="Capture duration in seconds (0=forever)",
    )
    _add_key_args(p_capture)

    # --- write ---
    p_write = sub.add_parser(
        "write",
        help="Write a value to the bike (use 'write list' to see writable fields)",
        allow_abbrev=False,
    )
    p_write.add_argument("field", help="Field name or 'list'")
    p_write.add_argument("value", nargs="?", default=None, help="Value to write")
    p_write.add_argument("address", nargs="?", default=None, help="BLE MAC address")
    p_write.add_argument("-p", "--pin", type=str, default=None, help="Pairing PIN")
    _add_key_args(p_write)

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    coro = {
        "scan": _cmd_scan,
        "telemetry": _cmd_telemetry,
        "read": _cmd_read,
        "services": _cmd_services,
        "capture": _cmd_capture,
        "write": _cmd_write,
    }[args.command](args)

    try:
        asyncio.run(coro)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except IdentificationError as exc:
        print(f"\nError: {exc}")
        sys.exit(1)
    except _CLI_ERRORS as exc:
        print(f"\nError: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
