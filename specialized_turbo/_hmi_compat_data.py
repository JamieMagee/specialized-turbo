"""
Compact HMI hardware-compatibility table.

This is an original re-expression, as plain Python data, of the *factual*
HMI-hardware-version-to-category groupings observed in the Specialized
app's ``assets/hmi_config/hmi_config.json`` (its ``hw_compatibility``
section only). It is not a copy of that file: the JSON asset itself is
proprietary app content and is intentionally **not** vendored or shipped
here, byte-identical or otherwise. Only the underlying facts needed for
``HmiType`` lookup -- which HW-version strings identify each HMI hardware
family -- are represented, in a format specific to this library.

``hw_replacement_exceptions`` (a separate section of that JSON, used by
the app for hardware-replacement/warranty logic) is not consulted by
``getHmiType``/``getBikeInfo`` and is deliberately excluded here.

Provenance: HW-version groupings observed via reverse engineering of
``libturbo-core.so`` (Specialized app 1.66.0) -- see the BLE
advertisement -> BikeInfo report for the full evidence. Refresh this table
if Specialized ships a new HMI hardware revision.
"""

from __future__ import annotations

# category name -> "X.Y.Z" HW-version strings that identify it.
# "TCUArterytek" is intentionally excluded from HmiType lookup (the native
# getHmiType() skips this category and returns UNKNOWN for those HW
# strings), but is retained here for completeness/documentation.
HW_COMPATIBILITY: dict[str, tuple[str, ...]] = {
    "TCU": ("A.1.0", "A.1.2"),
    "TCUArterytek": ("A.5.0", "A.5.1"),
    "TCDw": ("A.2.0",),
    "TCU2": ("B.4.3", "B.4.4", "A.4.4", "A.4.5", "A.4.6"),
    "TCDw2": ("B.3.2", "B.3.3", "A.3.3", "A.3.4", "A.3.5", "A.3.6"),
    "T3": ("A.6.0", "A.6.1", "A.6.2", "A.6.3", "A.6.4"),
    "H3": ("A.8.1", "A.8.2", "A.8.3", "A.8.4", "A.8.5"),
    "C4": ("A.7.0",),
    "T4": ("A.D.0",),
}
