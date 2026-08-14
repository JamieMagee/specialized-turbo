"""
Command-line interface for the Specialized Turbo Vado BLE library.

Provides subcommands for scanning, connecting, and reading telemetry.

Uses ``argparse`` (no extra dependencies) with optional ``click`` upgrade path.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from bleak.backends.characteristic import BleakGATTCharacteristic

from .connection import (
    SpecializedConnection,
    find_bike_advertisement_by_address,
    scan_for_bikes,
)
from .coordinator_helpers import parse_tcx_wire_payload
from .identification import IdentificationError
from .key_provider import EncryptionKeyProvider, EncryptionKeyProviderError
from .parameters import BikeParameter, all_tcx_fields, encode_parameter_id
from .protocol import (
    ProtocolEncryptionMethod,
    all_field_defs,
)
from .telemetry import run_telemetry_session
from .transport import BLETraceEvent, TraceCallback


class CLICommandError(RuntimeError):
    """A user-facing CLI failure without secret-bearing traceback output."""


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@asynccontextmanager
async def _key_provider(
    args: argparse.Namespace,
) -> AsyncIterator[EncryptionKeyProvider | None]:
    cloud = None
    if getattr(args, "email", None) is not None:
        try:
            from .cloud import SpecializedCloudClient
        except ImportError as exc:
            raise RuntimeError(
                "Account key retrieval requires `pip install specialized-turbo[cloud]`"
            ) from exc
        cloud = SpecializedCloudClient()
        await cloud.login(
            args.email,
            getpass.getpass("Specialized password: "),
        )

    try:
        yield cloud
    finally:
        if cloud is not None:
            await cloud.aclose()


@asynccontextmanager
async def _connection(
    args: argparse.Namespace,
    *,
    trace_callback: TraceCallback | None = None,
) -> AsyncIterator[SpecializedConnection]:
    async with (
        _key_provider(args) as provider,
        SpecializedConnection(
            args.address,
            pin=args.pin,
            key_provider=provider,
            wrapped_key=getattr(args, "wrapped_key", None),
            trace_callback=trace_callback,
        ) as connection,
    ):
        yield connection


def _add_key_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--wrapped-key", help="64-character wrapped bike key")
    group.add_argument(
        "--email",
        help="Specialized account email; password is prompted securely",
    )


async def _resolve_hmi_identifiers(
    args: argparse.Namespace,
) -> tuple[str | None, str, str]:
    hmi_hardware = args.hmi_hardware
    hmi_serial = args.hmi_serial
    if hmi_hardware is not None and hmi_serial is not None:
        return args.address, hmi_hardware, hmi_serial
    if args.address is None:
        raise CLICommandError(
            "provide a BLE address or both --hmi-hardware and --hmi-serial"
        )

    discovered = await find_bike_advertisement_by_address(
        args.address,
        timeout=args.scan_timeout,
    )
    if discovered is None:
        raise CLICommandError(
            f"could not find Specialized bike {args.address} during BLE scan"
        )

    _device, _raw, advertisement = discovered
    if advertisement.encryption != ProtocolEncryptionMethod.AES_CTR:
        raise CLICommandError("bike does not advertise the encrypted HMI key metadata")

    hmi_hardware = hmi_hardware or advertisement.hmi_hardware
    hmi_serial = hmi_serial or advertisement.hmi_serial
    if hmi_hardware is None or hmi_serial is None:
        raise CLICommandError("bike advertisement is missing HMI identifiers")
    return args.address, hmi_hardware, hmi_serial


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
        print(f"  Name:    {device.name or '(unknown)'}")
        print(f"  Address: {device.address}")
        print(f"  RSSI:    {adv.rssi} dBm")
        mfr = adv.manufacturer_data.get(0x0059, b"")
        if mfr:
            print(f"  Mfr:     {mfr.hex()}")
        print()


# ---------------------------------------------------------------------------
# fetch-key
# ---------------------------------------------------------------------------


async def _cmd_fetch_key(args: argparse.Namespace) -> None:
    """Retrieve the wrapped encryption key for one bike."""
    address, hmi_hardware, hmi_serial = await _resolve_hmi_identifiers(args)
    try:
        from .cloud import (
            CloudAuthenticationError,
            CloudRequestError,
            SpecializedCloudClient,
        )
    except ImportError as exc:
        raise CLICommandError(
            "fetch-key requires `pip install specialized-turbo[cloud]`"
        ) from exc

    try:
        async with SpecializedCloudClient() as cloud:
            await cloud.login(
                args.email,
                getpass.getpass("Specialized password: "),
            )
            wrapped_key = await cloud.get_wrapped_key(
                hmi_hardware=hmi_hardware,
                hmi_serial=hmi_serial,
            )
    except CloudAuthenticationError as exc:
        raise CLICommandError("Specialized account authentication failed") from exc
    except CloudRequestError as exc:
        raise CLICommandError("Specialized key retrieval failed") from exc

    if args.json_output:
        print(
            json.dumps(
                {
                    "address": address,
                    "hmi_hardware": hmi_hardware,
                    "hmi_serial": hmi_serial,
                    "wrapped_key": wrapped_key,
                },
                separators=(",", ":"),
            )
        )
    else:
        print(wrapped_key)


# ---------------------------------------------------------------------------
# telemetry
# ---------------------------------------------------------------------------


async def _cmd_telemetry(args: argparse.Namespace) -> None:
    """Connect and stream live telemetry."""
    print(f"Connecting to {args.address} ...")

    async with _key_provider(args) as provider:
        snapshot = await run_telemetry_session(
            args.address,
            pin=args.pin,
            duration=args.duration,
            output_format=args.format,
            key_provider=provider,
            wrapped_key=args.wrapped_key,
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

# Map human-readable names → TCX app-level parameter
_TCX_FIELD_NAME_MAP: dict[str, BikeParameter] = {}
for _param_id, _tfd in all_tcx_fields().items():
    _TCX_FIELD_NAME_MAP[_tfd.name] = BikeParameter(_param_id)


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
        for name, param in sorted(_TCX_FIELD_NAME_MAP.items()):
            tfd = all_tcx_fields()[int(param)]
            print(f"    {name:<28s}  (param={int(param)})  [{tfd.unit}]")
        return

    # Prefer TCX field lookup, fall back to TCU1
    tcx_param = _TCX_FIELD_NAME_MAP.get(field_name)
    tcu1_key = _FIELD_NAME_MAP.get(field_name)

    if tcx_param is None and tcu1_key is None:
        print(f"Unknown field: {field_name}")
        print("Use 'read list' to see available fields.")
        sys.exit(1)

    print(f"Connecting to {args.address} to read '{field_name}' ...")

    async with _connection(args) as conn:
        if tcx_param is not None:
            wire_msg = await conn.request_tcx_parameter(tcx_param)
            if wire_msg.nak_reason is not None:
                print(
                    f"{field_name}: rejected by bike "
                    f"(reason 0x{wire_msg.nak_reason:02x})"
                )
                return
            revision = conn.active_revision
            if revision is None:
                raise CLICommandError(
                    "TCX identification did not negotiate a protocol revision"
                )
            msg = parse_tcx_wire_payload(
                encode_parameter_id(wire_msg.wire_id) + wire_msg.data,
                revision,
            )
        else:
            assert tcu1_key is not None
            sender, channel = tcu1_key
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
                print(f"{field_name}: rejected by bike (reason 0x{msg.nak_reason:02x})")
            else:
                print(f"{msg.field_name} = {msg.converted_value} {msg.unit}")


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
        for name, (sender, channel) in sorted(_WRITABLE_FIELD_MAP.items()):
            fd = all_field_defs()[(sender, channel)]
            print(
                f"  {name:<28s}  (sender=0x{sender:02x} channel=0x{channel:02x})  [{fd.unit}]"
            )
        return

    if field_name not in _WRITABLE_FIELD_MAP:
        print(f"Unknown or read-only field: {field_name}")
        print("Use 'write list' to see writable fields.")
        sys.exit(1)

    if args.value is None or args.address is None:
        print("Usage: specialized-turbo write <field> <value> <address>")
        sys.exit(1)

    sender, channel = _WRITABLE_FIELD_MAP[field_name]
    fd = all_field_defs()[(sender, channel)]

    # Parse and encode the value
    raw_value = float(args.value) if "." in args.value else int(args.value)
    if fd.encode is not None:
        wire_value = fd.encode(raw_value)
    else:
        wire_value = int(raw_value)

    from .protocol import build_write_command

    data_bytes = wire_value.to_bytes(fd.data_size, "little")
    command = build_write_command(sender, channel, data_bytes)

    print(f"Connecting to {args.address} to write '{field_name}' = {raw_value} ...")

    async with _connection(args) as conn:
        await conn.write_command(command)
        print(
            f"Wrote {field_name} = {raw_value} (raw: {wire_value}, bytes: {command.hex()})"
        )


# ---------------------------------------------------------------------------
# services (debug helper)
# ---------------------------------------------------------------------------


async def _cmd_services(args: argparse.Namespace) -> None:
    """Connect and enumerate all GATT services/characteristics (debug)."""
    from bleak import BleakClient
    from bleak.exc import BleakError

    print(f"Connecting to {args.address} ...")
    async with BleakClient(args.address) as client:
        if args.pin is not None:
            try:
                await client.pair(protection_level=2)
            except (BleakError, NotImplementedError) as e:
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
    async with _connection(args, trace_callback=trace) as conn:
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


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="specialized-turbo",
        description="Interact with Specialized Turbo e-bikes over Bluetooth LE",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    # --- scan ---
    p_scan = sub.add_parser("scan", help="Scan for nearby Specialized bikes")
    p_scan.add_argument(
        "-t", "--timeout", type=float, default=10.0, help="Scan duration (seconds)"
    )

    # --- fetch-key ---
    p_fetch_key = sub.add_parser(
        "fetch-key",
        help="Retrieve a wrapped key for an encrypted bike",
        description=(
            "Retrieve the 64-character wrapped bike key. "
            "Requires specialized-turbo[cloud]."
        ),
    )
    p_fetch_key.add_argument(
        "address",
        nargs="?",
        help="BLE address; optional when both HMI identifiers are provided",
    )
    p_fetch_key.add_argument(
        "--email",
        required=True,
        help="Specialized account email; password is prompted securely",
    )
    p_fetch_key.add_argument("--hmi-hardware", help="HMI hardware version override")
    p_fetch_key.add_argument("--hmi-serial", help="HMI serial number override")
    p_fetch_key.add_argument(
        "--scan-timeout",
        type=float,
        default=10.0,
        help="BLE scan timeout in seconds",
    )
    p_fetch_key.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print address, HMI identifiers, and wrapped key as JSON",
    )

    # --- telemetry ---
    p_tel = sub.add_parser("telemetry", help="Stream live telemetry")
    p_tel.add_argument("address", help="BLE MAC address (e.g. DC:DD:BB:4A:D6:55)")
    p_tel.add_argument("-p", "--pin", type=str, default=None, help="Pairing PIN")
    _add_key_arguments(p_tel)
    p_tel.add_argument(
        "-d",
        "--duration",
        type=float,
        default=0,
        help="Duration in seconds (0=forever)",
    )
    p_tel.add_argument("-f", "--format", choices=["table", "json"], default="table")

    # --- read ---
    p_read = sub.add_parser(
        "read", help="Read a specific value (use 'read list' to see fields)"
    )
    p_read.add_argument("field", help="Field name or 'list'")
    p_read.add_argument("address", nargs="?", default=None, help="BLE MAC address")
    p_read.add_argument("-p", "--pin", type=str, default=None, help="Pairing PIN")
    _add_key_arguments(p_read)
    p_read.add_argument("-f", "--format", choices=["table", "json"], default="table")

    # --- services ---
    p_svc = sub.add_parser("services", help="Enumerate GATT services (debug)")
    p_svc.add_argument("address", help="BLE MAC address")
    p_svc.add_argument("-p", "--pin", type=str, default=None, help="Pairing PIN")

    # --- capture ---
    p_capture = sub.add_parser(
        "capture",
        help="Capture raw TCX writes and notifications",
    )
    p_capture.add_argument("address", help="BLE MAC address")
    p_capture.add_argument("-p", "--pin", type=str, default=None, help="Pairing PIN")
    _add_key_arguments(p_capture)
    p_capture.add_argument(
        "-d",
        "--duration",
        type=float,
        default=60,
        help="Capture duration in seconds (0=forever)",
    )

    # --- write ---
    p_write = sub.add_parser(
        "write",
        help="Write a value to the bike (use 'write list' to see writable fields)",
    )
    p_write.add_argument("field", help="Field name or 'list'")
    p_write.add_argument("value", nargs="?", default=None, help="Value to write")
    p_write.add_argument("address", nargs="?", default=None, help="BLE MAC address")
    p_write.add_argument("-p", "--pin", type=str, default=None, help="Pairing PIN")
    _add_key_arguments(p_write)

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    coro = {
        "scan": _cmd_scan,
        "fetch-key": _cmd_fetch_key,
        "telemetry": _cmd_telemetry,
        "read": _cmd_read,
        "services": _cmd_services,
        "capture": _cmd_capture,
        "write": _cmd_write,
    }[args.command](args)

    try:
        asyncio.run(coro)
    except CLICommandError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    except (IdentificationError, EncryptionKeyProviderError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    except KeyboardInterrupt:
        print("\nInterrupted.")


if __name__ == "__main__":
    main()
