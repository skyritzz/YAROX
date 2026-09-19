"""
Canonical Security Event contract (Phase 11).

This is the one typed, versioned shape that every event source — live HTTP
ingestion (``POST /events/ingest``) and dataset replay (``replay/engine.py``)
today, future connectors (Sysmon, Suricata EVE, Splunk HEC) tomorrow — is
normalized into before it reaches the event bus, storage (``models.event.Event``),
detection (``detection/engine.py``, ``detection/rules.py``) or correlation
(``correlation/engine.py``).

Design constraints this contract was written against (see
``docs/CANONICAL_EVENT_MODEL.md`` for the full mapping and rationale):

* ``hostname``/``user_name`` default to the literal string ``"unknown"``
  (never ``None``) when the source telemetry carries no value. This is an
  intentional, pre-existing convention: ``correlation/engine.py`` explicitly
  excludes ``"unknown"`` (case-insensitive) from entity matching, so an event
  without a real host/user is inert for correlation rather than erroring.
* ``event_type`` carries the taxonomy-normalized value when
  ``core.taxonomy.EventTaxonomyNormalizer`` recognizes it, with the original
  raw string preserved in ``metadata["raw_event_type"]`` — this is required
  for detection rule compatibility, since ``detection/rules.py`` matches
  ``event.event_type`` against literal strings such as ``"process creation"``.
* ``raw_log``/``metadata`` are preserved for the evidentiary chain of
  custody (Rule 5, CLAUDE.md) and are what ``detection/engine.py`` reads by
  plain dict access (``metadata["command_line"]``, ``metadata["process_name"]``,
  ``metadata["ip_address"]``) — this contract does not change that nesting.
* ``to_orm_kwargs()`` must remain constructor-compatible with
  ``models.event.Event`` and hash-compatible with ``core.integrity`` (which
  hashes ``timestamp, hostname, user_name, source, event_type, severity,
  raw_log, metadata`` — unaffected by anything added here, since ``event_id``
  is excluded from the hash by design, same as before).

Versioning
----------
``schema_version`` is a fixed literal, not a free string: introducing a
breaking change (a new required field, a changed default, a changed
validation rule that could reject previously-accepted input) requires adding
a new literal value and a new model class or migration path — it must never
be silently repointed at the same version string. Additive, backward
compatible changes (a new optional field) may stay on the same version.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Union

import dateutil.parser
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from core.taxonomy import CanonicalEventType, taxonomy_normalizer

CANONICAL_EVENT_SCHEMA_VERSION: Literal["1.0"] = "1.0"

VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
MAX_RAW_LOG_SIZE_BYTES = 65536  # 64 KB — matches schemas.ingest.MAX_PAYLOAD_SIZE_BYTES

UNKNOWN_SENTINEL = "unknown"


class CanonicalEventValidationError(ValueError):
    """Raised by ``from_raw`` when telemetry cannot be normalized into a CanonicalSecurityEvent."""


class CanonicalSecurityEvent(BaseModel):
    schema_version: Literal["1.0"] = Field(
        default=CANONICAL_EVENT_SCHEMA_VERSION,
        description="Canonical event contract version. See module docstring for the versioning policy.",
    )
    event_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description="Assigned once, at normalization time, by whichever path (live ingest or replay) first produces this event. Becomes models.event.Event.id.",
    )
    timestamp: datetime = Field(
        ..., description="When the event occurred, timezone-aware UTC. Unparseable or missing input falls back to now(UTC) rather than rejecting the event."
    )
    hostname: str = Field(UNKNOWN_SENTINEL, max_length=256, description="Originating host. 'unknown' sentinel when absent — see module docstring.")
    user_name: str = Field(UNKNOWN_SENTINEL, max_length=256, description="Associated user account. 'unknown' sentinel when absent — see module docstring.")
    source: str = Field(..., min_length=1, max_length=128, description="Log source identifier, e.g. 'sysmon', 'Suricata', 'yarox-synthetic-lab'.")
    event_type: str = Field(..., min_length=1, max_length=128, description="Taxonomy-normalized type when recognized, else the raw source value verbatim.")
    canonical_event_type: CanonicalEventType = Field(
        CanonicalEventType.UNKNOWN,
        description="Always set by this contract (not by the caller) from core.taxonomy.EventTaxonomyNormalizer.normalize(event_type, raw_log). Not currently a persisted column — see docs/CANONICAL_EVENT_MODEL.md.",
    )
    severity: str = Field("INFO", description=f"One of {sorted(VALID_SEVERITIES)}. Invalid non-empty values are rejected, not silently coerced.")
    raw_log: Dict[str, Any] = Field(..., description="Raw forensic payload, preserved verbatim. Non-dict input is wrapped as {'payload': str(...)}. Capped at 64 KB serialized.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Structured fields read by detection/entity-extraction via plain dict access.")

    @field_validator("timestamp", mode="before")
    @classmethod
    def _parse_timestamp(cls, v: Any) -> datetime:
        if v is None:
            return datetime.now(timezone.utc)
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        if isinstance(v, str) and v.strip():
            try:
                parsed = dateutil.parser.isoparse(v)
            except Exception:
                return datetime.now(timezone.utc)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc)

    @field_validator("hostname", "user_name", mode="before")
    @classmethod
    def _default_unknown(cls, v: Any) -> str:
        if v is None or (isinstance(v, str) and not v.strip()):
            return UNKNOWN_SENTINEL
        return v

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: Any) -> str:
        if not v:
            return "INFO"
        upper = str(v).strip().upper()
        if upper not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'. Allowed values: {sorted(VALID_SEVERITIES)}")
        return upper

    @field_validator("raw_log", mode="before")
    @classmethod
    def _coerce_raw_log(cls, v: Any) -> Dict[str, Any]:
        if isinstance(v, dict):
            return v
        return {"payload": str(v)}

    @field_validator("raw_log")
    @classmethod
    def _validate_raw_log_size(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        size = len(json.dumps(v).encode("utf-8"))
        if size > MAX_RAW_LOG_SIZE_BYTES:
            raise ValueError(f"raw_log size ({size} bytes) exceeds the {MAX_RAW_LOG_SIZE_BYTES}-byte (64 KB) limit.")
        return v

    @field_validator("metadata", mode="before")
    @classmethod
    def _coerce_metadata(cls, v: Any) -> Dict[str, Any]:
        if v is None:
            return {}
        if isinstance(v, dict):
            return v
        return {"info": str(v)}

    @model_validator(mode="after")
    def _apply_taxonomy(self) -> "CanonicalSecurityEvent":
        canonical = taxonomy_normalizer.normalize(self.event_type, self.raw_log)
        self.canonical_event_type = canonical
        if canonical != CanonicalEventType.UNKNOWN and self.event_type != canonical.value:
            self.metadata.setdefault("raw_event_type", self.event_type)
            self.event_type = canonical.value
        return self

    @classmethod
    def from_raw(cls, raw_data: Dict[str, Any]) -> "CanonicalSecurityEvent":
        """
        Adapter from heterogeneous raw telemetry (the live-ingest request body,
        or a replay dataset record) into the canonical contract. Field-selection
        fallbacks here mirror the pre-Phase-11 plugins.parsers.generic.GenericJSONParser
        exactly, so existing callers see no behavior change beyond the validation
        tightened in the field validators above (see docs/CANONICAL_EVENT_MODEL.md).
        """
        if not isinstance(raw_data, dict):
            raise CanonicalEventValidationError(f"raw event data must be a JSON object, got {type(raw_data).__name__}")

        raw_log = raw_data.get("raw_log", raw_data)
        if not isinstance(raw_log, dict):
            raw_log = {"payload": str(raw_log)}

        metadata = raw_data.get("metadata") or raw_log.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {"info": str(metadata)}

        hostname = raw_data.get("hostname") or raw_log.get("hostname") or UNKNOWN_SENTINEL
        user_name = (
            raw_data.get("user_name")
            or raw_data.get("user")
            or raw_log.get("user_name")
            or raw_log.get("user")
            or UNKNOWN_SENTINEL
        )

        try:
            return cls(
                timestamp=raw_data.get("timestamp"),
                hostname=hostname,
                user_name=user_name,
                source=raw_data.get("source") or "generic",
                event_type=raw_data.get("event_type") or "unknown",
                severity=raw_data.get("severity", "INFO"),
                raw_log=raw_log,
                metadata=metadata,
            )
        except ValidationError as e:
            raise CanonicalEventValidationError(str(e)) from e

    def to_orm_kwargs(self) -> Dict[str, Any]:
        """Shape matching models.event.Event's constructor exactly (metadata_, not metadata)."""
        return {
            "id": self.event_id,
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "user_name": self.user_name,
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity,
            "raw_log": self.raw_log,
            "metadata_": self.metadata,
        }
