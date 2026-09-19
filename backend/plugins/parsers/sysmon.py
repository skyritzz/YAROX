"""
Sysmon connector (Phase 11, connector #1).

Parses telemetry from Sysinternals Sysmon (the ``Microsoft-Windows-Sysmon/Operational``
channel), in the flattened JSON shape produced by common shippers (Winlogbeat,
NXLog) — not raw EVTX/XML. Supports the three most common, security-relevant
Sysmon event types:

    EventID 1  (Process Create)  -> PROCESS_EXECUTION (existing taxonomy mapping)
    EventID 3  (Network Connect) -> NETWORK_TRAFFIC    (existing taxonomy mapping)
    EventID 11 (File Create)     -> FILE_OPERATION      (mapping added to
                                     core/taxonomy.py by this phase — previously
                                     unreachable, see docs/CANONICAL_EVENT_MODEL.md)

Deliberately out of scope: Windows Security auditing events (4624/4625/4672)
are a *different* provider (the built-in Security channel, not Sysmon —
Sysmon is a separate Sysinternals tool that only emits its own event IDs).
core.taxonomy already maps those IDs for whichever future connector accepts
them; bundling them here under the "Sysmon" name would misrepresent their
actual source. See docs/CANONICAL_EVENT_MODEL.md "Connectors" for the
reasoning and how to add that connector separately.

This module transforms Sysmon's field names into the generic raw-shape that
schemas.canonical_event.CanonicalSecurityEvent.from_raw() already validates
(reusing the one canonical contract, not a parallel one), then returns
Event-ORM-constructor kwargs exactly like plugins.parsers.generic.GenericJSONParser
does — the same ParserInterface, so callers (the new /events/ingest/sysmon
endpoint) don't need special-case handling.
"""
from typing import Any, Dict, Optional

import dateutil.parser

from plugins.parsers.generic import ParserInterface
from schemas.canonical_event import CanonicalEventValidationError, CanonicalSecurityEvent

# EventIDs this connector accepts. Anything else is rejected explicitly rather
# than silently normalized to UNKNOWN — a connector should know what it supports.
SUPPORTED_EVENT_IDS = {1, 3, 11}

SYSMON_SOURCE = "sysmon"

_EVENT_TYPE_LABELS = {
    1: "Process Creation",
    3: "Network Connection",
    11: "File Create",
}


def _strip_domain(user: Optional[str]) -> Optional[str]:
    """'WORKSTATION-01\\jdoe' / 'DOMAIN\\jdoe' -> 'jdoe', matching the bare
    usernames used across the rest of the system (detection rules, correlation,
    replay datasets all key on bare usernames, not DOMAIN\\user)."""
    if not user:
        return user
    return user.split("\\")[-1] if "\\" in user else user


def _basename(path: Optional[str]) -> Optional[str]:
    """'C:\\Windows\\System32\\cmd.exe' -> 'cmd.exe'."""
    if not path:
        return path
    return path.replace("/", "\\").split("\\")[-1]


class SysmonParser(ParserInterface):
    """Normalizer for Sysmon telemetry (Winlogbeat/NXLog-style flattened JSON)."""

    def parse(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        return self.to_canonical(raw_data).to_orm_kwargs()

    def to_canonical(self, raw_data: Dict[str, Any]) -> CanonicalSecurityEvent:
        if not isinstance(raw_data, dict):
            raise CanonicalEventValidationError(f"Sysmon event must be a JSON object, got {type(raw_data).__name__}")

        raw_event_id = raw_data.get("EventID")
        if raw_event_id is None:
            raise CanonicalEventValidationError("Sysmon event is missing required field 'EventID'")
        try:
            event_id = int(raw_event_id)
        except (TypeError, ValueError):
            raise CanonicalEventValidationError(f"Sysmon event 'EventID' must be an integer, got {raw_event_id!r}")
        if event_id not in SUPPORTED_EVENT_IDS:
            raise CanonicalEventValidationError(
                f"Unsupported Sysmon EventID {event_id}. This connector supports "
                f"{sorted(SUPPORTED_EVENT_IDS)} (Process Create, Network Connect, File Create)."
            )

        hostname = raw_data.get("Hostname") or raw_data.get("Computer")
        user_name = _strip_domain(raw_data.get("User"))

        timestamp = None
        utc_time = raw_data.get("UtcTime")
        if utc_time:
            try:
                # Sysmon's UtcTime ("YYYY-MM-DD HH:MM:SS.fff") is not strict ISO-8601
                # (space, not 'T') — dateutil.parser.parse() is the lenient general
                # parser (unlike the canonical contract's own strict isoparse), so we
                # resolve it here and hand the contract a real datetime object.
                timestamp = dateutil.parser.parse(utc_time)
            except (ValueError, OverflowError):
                timestamp = None  # contract falls back to now(UTC); not a hard failure

        metadata: Dict[str, Any] = {"process_name": _basename(raw_data.get("Image"))}

        if event_id == 1:
            metadata["command_line"] = raw_data.get("CommandLine")
            metadata["parent_process"] = _basename(raw_data.get("ParentImage"))
            metadata["parent_command_line"] = raw_data.get("ParentCommandLine")
            if raw_data.get("Hashes"):
                metadata["hashes"] = raw_data["Hashes"]
        elif event_id == 3:
            dest_ip = raw_data.get("DestinationIp")
            # Both keys point at the same value: detection/engine.py's entity
            # extraction reads metadata.ip_address, while some existing dataset
            # fixtures use metadata.destination_ip (see docs/CANONICAL_EVENT_MODEL.md
            # "Known limitations" from Phase 11) — setting both here closes that
            # gap for events this connector itself produces.
            metadata["ip_address"] = dest_ip
            metadata["destination_ip"] = dest_ip
            metadata["destination_port"] = raw_data.get("DestinationPort")
            metadata["source_ip"] = raw_data.get("SourceIp")
            metadata["protocol"] = raw_data.get("Protocol")
        elif event_id == 11:
            metadata["target_filename"] = raw_data.get("TargetFilename")

        transformed = {
            "timestamp": timestamp,
            "hostname": hostname,
            "user_name": user_name,
            "source": SYSMON_SOURCE,
            "event_type": _EVENT_TYPE_LABELS[event_id],
            "severity": "INFO",  # Sysmon carries no native severity; detection rules assign it on match
            "raw_log": raw_data,  # preserved verbatim, including the original EventID, for chain of custody
            "metadata": metadata,
        }
        return CanonicalSecurityEvent.from_raw(transformed)


sysmon_parser = SysmonParser()
