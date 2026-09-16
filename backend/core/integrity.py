"""
Event integrity hashing (SHA-256).

What is hashed
--------------
The evidentiary content of a normalized event exactly as it is persisted:

    timestamp, hostname, user_name, source, event_type, severity,
    raw_log, metadata

The row ``id`` and ``payload_sha256`` itself are excluded, so two events with
identical content produce the same hash (useful for duplicate detection).

Canonicalization (version ``yarox-event-v1``)
---------------------------------------------
1. Build a JSON object with exactly the keys above, plus ``"hash_version"``.
2. ``timestamp`` is converted to UTC and rendered with
   ``datetime.isoformat()`` (``YYYY-MM-DDTHH:MM:SS[.ffffff]+00:00``).
   Naive datetimes are treated as UTC.
3. Missing ``hostname``/``user_name``/``metadata`` are encoded as JSON ``null``.
4. Serialize with ``json.dumps(sort_keys=True, separators=(",", ":"),
   ensure_ascii=False, allow_nan=False)``; nested object keys are sorted too.
5. Encode as UTF-8 and compute the SHA-256 hex digest (64 lowercase chars).

The hash is computed once, when the event is first stored. Events stored before
this hashing existed have ``payload_sha256 = NULL``; no hash is fabricated for
them after the fact.
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

HASH_VERSION = "yarox-event-v1"
HASHED_FIELDS = ("timestamp", "hostname", "user_name", "source", "event_type", "severity", "raw_log", "metadata")


def _canonical_timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    raise TypeError(f"Event timestamp must be a datetime, got {type(value).__name__}")


def canonical_event_payload(event_fields: Mapping[str, Any]) -> str:
    """
    Returns the canonical JSON string for an event.
    ``event_fields`` may use either ``metadata`` or the ORM attribute name ``metadata_``.
    """
    metadata = event_fields.get("metadata", event_fields.get("metadata_"))
    document: Dict[str, Any] = {
        "hash_version": HASH_VERSION,
        "timestamp": _canonical_timestamp(event_fields.get("timestamp")),
        "hostname": event_fields.get("hostname"),
        "user_name": event_fields.get("user_name"),
        "source": event_fields.get("source"),
        "event_type": event_fields.get("event_type"),
        "severity": event_fields.get("severity"),
        "raw_log": event_fields.get("raw_log"),
        "metadata": metadata,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def compute_event_hash(event_fields: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_event_payload(event_fields).encode("utf-8")).hexdigest()


def event_fields_from_model(event: Any) -> Dict[str, Any]:
    return {
        "timestamp": event.timestamp,
        "hostname": event.hostname,
        "user_name": event.user_name,
        "source": event.source,
        "event_type": event.event_type,
        "severity": event.severity,
        "raw_log": event.raw_log,
        "metadata": event.metadata_,
    }


def verify_event_integrity(event: Any) -> Optional[bool]:
    """
    Recomputes the hash of a stored event and compares it with the stored value.
    Returns None when the event was stored without a hash (legacy row).
    """
    if not getattr(event, "payload_sha256", None):
        return None
    return compute_event_hash(event_fields_from_model(event)) == event.payload_sha256
