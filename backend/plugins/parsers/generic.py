from abc import ABC, abstractmethod
from typing import Dict, Any, Union
from datetime import datetime, timezone
import dateutil.parser
from core.taxonomy import taxonomy_normalizer, CanonicalEventType

class ParserInterface(ABC):
    @abstractmethod
    def parse(self, raw_data: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
        """
        Parses raw event data into the normalized schema.
        Returns a dictionary matching the Event ORM schema.
        """
        pass

class GenericJSONParser(ParserInterface):
    """
    Standard normalizer for incoming JSON telemetry and synthetic lab events.
    Applies canonical taxonomy mapping while preserving raw logs and metadata.
    """
    def parse(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        # 1. Parse timestamp with safe fallback
        timestamp_raw = raw_data.get("timestamp")
        if isinstance(timestamp_raw, datetime):
            timestamp = timestamp_raw
        elif isinstance(timestamp_raw, str) and timestamp_raw.strip():
            try:
                timestamp = dateutil.parser.isoparse(timestamp_raw)
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
            except Exception:
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

        # 2. Extract and sanitize raw log and metadata
        raw_log = raw_data.get("raw_log", raw_data)
        if not isinstance(raw_log, dict):
            raw_log = {"payload": str(raw_log)}

        metadata = raw_data.get("metadata") or raw_log.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {"info": str(metadata)}

        # 3. Severity normalization
        severity = str(raw_data.get("severity", "INFO")).upper()
        if severity not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            severity = "INFO"

        # 4. Canonical event type normalization
        raw_event_type = raw_data.get("event_type", "unknown")
        canonical_type = taxonomy_normalizer.normalize(raw_event_type, raw_log)
        
        # Set normalized event type while preserving raw in metadata
        if canonical_type != CanonicalEventType.UNKNOWN:
            event_type = canonical_type.value
            metadata["raw_event_type"] = raw_event_type
        else:
            event_type = raw_event_type

        return {
            "timestamp": timestamp,
            "hostname": raw_data.get("hostname") or raw_log.get("hostname") or "unknown",
            "user_name": raw_data.get("user_name") or raw_data.get("user") or raw_log.get("user_name") or raw_log.get("user") or "unknown",
            "source": raw_data.get("source", "generic"),
            "event_type": event_type,
            "severity": severity,
            "raw_log": raw_log,
            "metadata_": metadata
        }

generic_parser = GenericJSONParser()
