from abc import ABC, abstractmethod
from typing import Dict, Any
from datetime import datetime, timezone
import dateutil.parser

class ParserInterface(ABC):
    @abstractmethod
    def parse(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses raw event data into the normalized schema.
        Returns a dictionary matching the Event schema.
        """
        pass

class GenericJSONParser(ParserInterface):
    """
    A generic parser for events that already loosely match our target schema.
    """
    def parse(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        timestamp_str = raw_data.get("timestamp")
        if timestamp_str:
            timestamp = dateutil.parser.isoparse(timestamp_str)
        else:
            timestamp = datetime.now(timezone.utc)

        return {
            "timestamp": timestamp,
            "hostname": raw_data.get("hostname", "unknown"),
            "user_name": raw_data.get("user") or raw_data.get("user_name") or "unknown",
            "source": raw_data.get("source", "generic"),
            "event_type": raw_data.get("event_type", "unknown"),
            "severity": raw_data.get("severity", "INFO"),
            "raw_log": raw_data.get("raw_log", raw_data),
            "metadata_": raw_data.get("raw_log", {}).get("metadata") or raw_data.get("metadata", {})
        }
