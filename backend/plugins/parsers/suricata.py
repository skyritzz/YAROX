"""
Suricata EVE JSON connector (Phase 11, connector #2).

Parses Suricata's EVE JSON output (``eve.json``), the flow-oriented,
line-delimited JSON emitted by the Suricata IDS/IPS engine — not the (legacy,
non-JSON) unified2 or fast.log formats. Each EVE record is discriminated by
its own top-level ``event_type`` field (Suricata's field name, not to be
confused with the canonical contract's own ``event_type`` concept — this
module reads the former to decide how to populate the latter). Supports the
two EVE record types most relevant to an investigation platform:

    "alert" -> SYSTEM_ALERT   (a NIDS signature match: the record that
                                carries an actual security finding, e.g.
                                "ET TROJAN Cobalt Strike Beaconing Detected")
    "flow"  -> NETWORK_TRAFFIC (a completed/updated connection record: raw
                                network telemetry for correlation, no
                                built-in severity)

Both taxonomy mappings ("suricata alert", "network flow") are new, additive
entries in core/taxonomy.py — SYSTEM_ALERT was defined in the
CanonicalEventType enum but had no string/ID mapping reaching it before this
connector (unreachable, same situation FILE_OPERATION was in before the
Sysmon connector). No detection rule currently targets SYSTEM_ALERT or
NETWORK_TRAFFIC (see docs/CANONICAL_EVENT_MODEL.md "How to add another
connector", step 7, and YAROX_REALITY_AUDIT.md D-4/D-5) — a Suricata alert is
stored, hashed, and available as evidence exactly like any other event, but
does not by itself create an InvestigationCase yet. That gap is Phase 13
detection-rule work, not a defect in this connector.

Deliberately out of scope for this connector: EVE's other record types
("dns", "http", "tls", "fileinfo", "stats", "netflow", ...) — each carries a
different, non-overlapping field shape and would need its own explicit
mapping to avoid silently misrepresenting fields that aren't actually there.
Add them the same way this connector added "flow" if/when a real use case
needs them (see docs/CANONICAL_EVENT_MODEL.md "Connectors").

Like the Sysmon connector, this transforms Suricata's field names into the
generic raw-shape that schemas.canonical_event.CanonicalSecurityEvent.from_raw()
already validates, then returns Event-ORM-constructor kwargs via the same
ParserInterface plugins.parsers.generic.GenericJSONParser implements.
"""
from typing import Any, Dict, Optional

import dateutil.parser

from plugins.parsers.generic import ParserInterface
from schemas.canonical_event import CanonicalEventValidationError, CanonicalSecurityEvent

# Suricata's own top-level 'event_type' discriminator values this connector accepts.
SUPPORTED_EVE_EVENT_TYPES = {"alert", "flow"}

SURICATA_SOURCE = "suricata"

_EVENT_TYPE_LABELS = {
    "alert": "Suricata Alert",
    "flow": "Network Flow",
}

# Suricata/ET convention: lower numbers are higher priority (1 = highest).
# Mapped conservatively — this connector normalizes vendor severity, it does
# not decide investigation severity (no detection rule reads it yet; see
# module docstring). Missing or out-of-range values fall back to "LOW" rather
# than "INFO", since an EVE 'alert' record is, by definition, always a
# signature match and therefore never merely informational.
_ALERT_SEVERITY_MAP = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
_DEFAULT_ALERT_SEVERITY = "LOW"


def _parse_timestamp(raw: Optional[str]):
    if not raw:
        return None
    try:
        # EVE's timestamp ("2026-09-20T10:15:22.123456+0000") uses a
        # colon-less UTC offset that isoparse (the canonical contract's own
        # strict parser) does not reliably accept — dateutil.parser.parse()
        # is the lenient general parser, same choice made in the Sysmon
        # connector for its own non-strict timestamp format.
        return dateutil.parser.parse(raw)
    except (ValueError, OverflowError):
        return None  # contract falls back to now(UTC); not a hard failure


class SuricataParser(ParserInterface):
    """Normalizer for Suricata EVE JSON records ('alert' and 'flow')."""

    def parse(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        return self.to_canonical(raw_data).to_orm_kwargs()

    def to_canonical(self, raw_data: Dict[str, Any]) -> CanonicalSecurityEvent:
        if not isinstance(raw_data, dict):
            raise CanonicalEventValidationError(f"Suricata EVE event must be a JSON object, got {type(raw_data).__name__}")

        eve_event_type = raw_data.get("event_type")
        if not eve_event_type:
            raise CanonicalEventValidationError("Suricata EVE event is missing required field 'event_type'")
        if eve_event_type not in SUPPORTED_EVE_EVENT_TYPES:
            raise CanonicalEventValidationError(
                f"Unsupported Suricata EVE event_type '{eve_event_type}'. This connector supports "
                f"{sorted(SUPPORTED_EVE_EVENT_TYPES)} (alert, flow)."
            )

        timestamp = _parse_timestamp(raw_data.get("timestamp"))
        # EVE carries no built-in host identity for the traffic's endpoint(s)
        # (it observes the wire, not a process) — 'host' is the sensor's own
        # hostname, populated only when Suricata's optional 'host-info'
        # EVE output extension is enabled. Absent it, the contract's own
        # UNKNOWN_SENTINEL default applies, same as any source with no host.
        hostname = raw_data.get("host")

        dest_ip = raw_data.get("dest_ip")
        metadata: Dict[str, Any] = {
            "source_ip": raw_data.get("src_ip"),
            "source_port": raw_data.get("src_port"),
            "destination_ip": dest_ip,
            # Mirrors the Sysmon connector's dual-key convention: detection/
            # entity-extraction code reads metadata.ip_address; some existing
            # fixtures/rules read metadata.destination_ip. Both point at the
            # same value here for the same compatibility reason.
            "ip_address": dest_ip,
            "destination_port": raw_data.get("dest_port"),
            "protocol": raw_data.get("proto"),
        }

        if eve_event_type == "alert":
            alert = raw_data.get("alert")
            if not isinstance(alert, dict) or not alert.get("signature"):
                raise CanonicalEventValidationError(
                    "Suricata EVE 'alert' event is missing a required 'alert.signature' field"
                )
            metadata["signature"] = alert.get("signature")
            metadata["signature_id"] = alert.get("signature_id")
            metadata["category"] = alert.get("category")
            metadata["alert_action"] = alert.get("action")
            metadata["suricata_severity"] = alert.get("severity")
            severity = _ALERT_SEVERITY_MAP.get(alert.get("severity"), _DEFAULT_ALERT_SEVERITY)
        else:  # "flow"
            flow = raw_data.get("flow") if isinstance(raw_data.get("flow"), dict) else {}
            metadata["app_proto"] = raw_data.get("app_proto")
            metadata["bytes_toserver"] = flow.get("bytes_toserver")
            metadata["bytes_toclient"] = flow.get("bytes_toclient")
            metadata["pkts_toserver"] = flow.get("pkts_toserver")
            metadata["pkts_toclient"] = flow.get("pkts_toclient")
            metadata["flow_state"] = flow.get("state")
            severity = "INFO"  # a flow record is raw telemetry, not itself a finding

        transformed = {
            "timestamp": timestamp,
            "hostname": hostname,
            "source": SURICATA_SOURCE,
            "event_type": _EVENT_TYPE_LABELS[eve_event_type],
            "severity": severity,
            "raw_log": raw_data,  # preserved verbatim, including the original EVE record, for chain of custody
            "metadata": metadata,
        }
        return CanonicalSecurityEvent.from_raw(transformed)


suricata_parser = SuricataParser()
