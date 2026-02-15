"""
specialized_turbo — Python library for Specialized Turbo e-bike BLE communication.

Quick start::

    import asyncio
    from specialized_turbo import SpecializedConnection, TelemetryMonitor

    async def main():
        async with SpecializedConnection("DC:DD:BB:4A:D6:55", pin=946166) as conn:
            monitor = TelemetryMonitor(conn)
            await monitor.start()

            async for msg in monitor.stream():
                print(f"{msg.field_name} = {msg.converted_value} {msg.unit}")

    asyncio.run(main())
"""

from .protocol import (
    # UUIDs
    SERVICE_DATA_NOTIFY,
    SERVICE_DATA_REQUEST,
    SERVICE_DATA_WRITE,
    CHAR_NOTIFY,
    CHAR_REQUEST_READ,
    CHAR_REQUEST_WRITE,
    CHAR_WRITE,
    # Enums
    Sender,
    BatteryChannel,
    MotorChannel,
    BikeSettingsChannel,
    AssistLevel,
    # Parsing
    parse_message,
    ParsedMessage,
    FieldDefinition,
    get_field_def,
    all_field_defs,
    build_request,
    is_specialized_advertisement,
)
from .models import (
    BatteryState,
    MotorState,
    BikeSettings,
    TelemetrySnapshot,
)
from .connection import (
    SpecializedConnection,
    scan_for_bikes,
    find_bike_by_address,
)
from .telemetry import (
    TelemetryMonitor,
    run_telemetry_session,
)

__all__ = [
    # Protocol
    "SERVICE_DATA_NOTIFY",
    "SERVICE_DATA_REQUEST",
    "SERVICE_DATA_WRITE",
    "CHAR_NOTIFY",
    "CHAR_REQUEST_READ",
    "CHAR_REQUEST_WRITE",
    "CHAR_WRITE",
    "Sender",
    "BatteryChannel",
    "MotorChannel",
    "BikeSettingsChannel",
    "AssistLevel",
    "parse_message",
    "ParsedMessage",
    "FieldDefinition",
    "get_field_def",
    "all_field_defs",
    "build_request",
    "is_specialized_advertisement",
    # Models
    "BatteryState",
    "MotorState",
    "BikeSettings",
    "TelemetrySnapshot",
    # Connection
    "SpecializedConnection",
    "scan_for_bikes",
    "find_bike_by_address",
    # Telemetry
    "TelemetryMonitor",
    "run_telemetry_session",
]

__version__ = "0.1.0"
