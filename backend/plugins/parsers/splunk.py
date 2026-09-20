"""
Splunk HTTP Event Collector (HEC) connector (Phase 11, connector #3).

Parses the JSON envelope Splunk's HEC protocol uses
(``POST .../services/collector/event``): a transport wrapper —
``{"time": <epoch>, "host": ..., "source": ..., "sourcetype": ..., "index":
..., "event": {...}}`` — around an inner ``event`` payload. This connector
targets the inner payload shaped as a Splunk Common Information Model (CIM)
Alert (the shape a Splunk "Alert Action" webhook forwards for a matched
correlation search — see docs/YAROX_ARCHITECTURAL_RECONSTRUCTION.md
"Ingestion Mechanisms" and its Connector Transformation Matrix, the row
labelled "Splunk CIM Alert"), reading CIM's own field names: ``_time``,
``dest``/``dvc``, ``user``, ``app``, ``signature``, ``severity``, ``src``,
``dest_ip``.

Deliberately different in shape from the Sysmon/Suricata connectors: those
sources have a closed, enumerable set of event/EventIDs, so each explicitly
enumerates what it supports and rejects everything else. Splunk HEC has no
such closed set by design — a HEC stream can carry an alert with literally
any ``signature`` text from any correlation search an operator has written.
This connector's job is therefore CIM field-name translation (the same
translation Sysmon/Suricata do for their own vendor fields), not
event-type enumeration; classification of the resulting ``event_type``
string is left to the same generic taxonomy heuristics
(``core.taxonomy.EventTaxonomyNormalizer``) that ``plugins.parsers.generic.
GenericJSONParser`` already relies on for the live-ingest path — no new
taxonomy mapping is added by this connector, unlike Sysmon (EventID 11) or
Suricata (``alert``/``flow``).

What *is* validated and rejected explicitly: the outer envelope must be a
JSON object with an ``event`` key (the one thing every HEC payload has by
protocol definition), and ``event`` itself must be a JSON object, not a raw
string. HEC officially allows raw-text events, but this connector cannot
extract CIM fields (``dest``, ``user``, ``signature``, ...) from unstructured
text without a parsing layer this phase does not add — accepting a raw
string and returning an empty/fabricated metadata dict would misrepresent
what was actually extracted (CLAUDE.md Rule 2/Rule 5), so it is rejected
with a clear message instead.
"""
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from plugins.parsers.generic import ParserInterface
from schemas.canonical_event import CanonicalEventValidationError, CanonicalSecurityEvent

SPLUNK_SOURCE = "splunk"

_DEFAULT_EVENT_TYPE = "Splunk HEC Event"

# Splunk CIM's own Alerts datamodel severity values (case-insensitive on input).
_CIM_SEVERITY_MAP = {
    "informational": "INFO",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}


def _strip_domain(user: Optional[str]) -> Optional[str]:
    """'CORP\\jdoe' -> 'jdoe', matching the bare usernames used across the rest
    of the system. Same rule as plugins.parsers.sysmon._strip_domain; kept as
    a local copy rather than a shared import so each connector stays a
    self-contained module reading only its own vendor's field names (the
    Suricata connector follows the same convention with no fields to strip)."""
    if not user:
        return user
    return user.split("\\")[-1] if "\\" in user else user


def _parse_epoch(value: Any) -> Optional[datetime]:
    """HEC's 'time' and CIM's '_time' are both Unix epoch seconds (optionally
    fractional, e.g. 1433188255.253), not ISO-8601 strings - the canonical
    contract's own timestamp parser expects ISO strings, so this connector
    resolves epoch values itself and hands the contract a real datetime,
    same rationale as the Sysmon/Suricata connectors' own timestamp handling."""
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None  # contract falls back to now(UTC); not a hard failure


class SplunkHECParser(ParserInterface):
    """Normalizer for Splunk HEC envelopes carrying a CIM-style Alert event."""

    def parse(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        return self.to_canonical(raw_data).to_orm_kwargs()

    def to_canonical(self, raw_data: Dict[str, Any]) -> CanonicalSecurityEvent:
        if not isinstance(raw_data, dict):
            raise CanonicalEventValidationError(f"Splunk HEC payload must be a JSON object, got {type(raw_data).__name__}")

        if "event" not in raw_data:
            raise CanonicalEventValidationError("Splunk HEC payload is missing required field 'event'")

        event = raw_data["event"]
        if not isinstance(event, dict):
            raise CanonicalEventValidationError(
                "Splunk HEC 'event' must be a JSON object with CIM-style fields "
                "(e.g. 'signature', 'dest', 'user'); raw string events are not "
                "supported by this connector."
            )

        # CIM's own '_time' (inside the event, when the source forwards it) takes
        # priority over HEC's transport-level 'time' (when Splunk itself stamped
        # receipt) - the former is closer to when the underlying activity occurred.
        timestamp = _parse_epoch(event.get("_time")) or _parse_epoch(raw_data.get("time"))

        # Per docs/YAROX_ARCHITECTURAL_RECONSTRUCTION.md's Connector Transformation
        # Matrix: CIM 'dest'/'dvc' map to hostname (entity resolution), not to an
        # IP field - 'dest_ip'/'src' are the separate, disambiguated network fields.
        hostname = event.get("dest") or event.get("dvc")
        user_name = _strip_domain(event.get("user"))

        metadata: Dict[str, Any] = {
            # Splunk's own per-record provenance fields, kept distinct from this
            # connector's 'source' ("splunk") to avoid conflating YAROX's
            # connector-identity column with Splunk's own routing metadata.
            "splunk_source": raw_data.get("source"),
            "splunk_sourcetype": raw_data.get("sourcetype"),
            "splunk_index": raw_data.get("index"),
            "signature": event.get("signature"),
            # Preserved as-is, not forced into 'protocol' or 'process_name': CIM's
            # 'app' names the reporting application/technology (e.g. 'win:security'),
            # which is neither reliably a network protocol nor a process name -
            # mapping it into either would fabricate a fact this field doesn't
            # actually state (CLAUDE.md Rule 2/Rule 5). A documented, deliberate
            # narrowing of the architecture doc's "app -> protocol / process_name"
            # suggestion, not an oversight.
            "app": event.get("app"),
        }
        if event.get("src"):
            metadata["source_ip"] = event.get("src")
        dest_ip = event.get("dest_ip")
        if dest_ip:
            metadata["destination_ip"] = dest_ip
            metadata["ip_address"] = dest_ip  # same dual-key convention as the Sysmon/Suricata connectors

        severity = _CIM_SEVERITY_MAP.get(str(event.get("severity")).strip().lower(), "INFO")

        transformed = {
            "timestamp": timestamp,
            "hostname": hostname,
            "user_name": user_name,
            "source": SPLUNK_SOURCE,
            # No fixed enum to validate against (see module docstring) - the raw
            # CIM 'signature', or Splunk's own 'sourcetype' as a fallback, is
            # handed to the existing generic taxonomy normalizer exactly as
            # plugins.parsers.generic.GenericJSONParser already does for
            # unstructured live-ingest payloads.
            "event_type": event.get("signature") or raw_data.get("sourcetype") or _DEFAULT_EVENT_TYPE,
            "severity": severity,
            "raw_log": raw_data,  # preserved verbatim, including the full HEC envelope, for chain of custody
            "metadata": metadata,
        }
        return CanonicalSecurityEvent.from_raw(transformed)


splunk_hec_parser = SplunkHECParser()
