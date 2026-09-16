from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, Any, Union
from datetime import datetime
import json

VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
MAX_PAYLOAD_SIZE_BYTES = 65536  # 64 KB

class IngestEventRequest(BaseModel):
    timestamp: Optional[str] = Field(None, description="ISO timestamp of the event (defaults to current UTC time if omitted)")
    hostname: Optional[str] = Field(None, max_length=256, description="Originating host or server name")
    user_name: Optional[str] = Field(None, max_length=256, description="Associated user account")
    source: str = Field(..., min_length=1, max_length=128, description="Log source identifier, e.g., 'yarox-synthetic-lab', 'sysmon', 'auditd'")
    event_type: str = Field(..., min_length=1, max_length=128, description="Event classification, e.g., 'Process Creation', 'Authentication Failure'")
    severity: Optional[str] = Field("INFO", description="Severity level: INFO, LOW, MEDIUM, HIGH, CRITICAL")
    raw_log: Union[Dict[str, Any], str] = Field(..., description="Raw forensic telemetry payload")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Structured event metadata")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: Optional[str]) -> str:
        if not v:
            return "INFO"
        upper_v = v.strip().upper()
        if upper_v not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'. Allowed values: {sorted(list(VALID_SEVERITIES))}")
        return upper_v

    @field_validator("raw_log")
    @classmethod
    def validate_payload_size(cls, v: Union[Dict[str, Any], str]) -> Union[Dict[str, Any], str]:
        serialized = json.dumps(v) if isinstance(v, dict) else str(v)
        if len(serialized.encode("utf-8")) > MAX_PAYLOAD_SIZE_BYTES:
            raise ValueError(f"Payload size ({len(serialized.encode('utf-8'))} bytes) exceeds maximum allowable limit of {MAX_PAYLOAD_SIZE_BYTES} bytes (64 KB).")
        return v

class IngestEventResponse(BaseModel):
    status: str = "accepted"
    event_id: str
    timestamp: str
    source: str
    event_type: str
    ingest_mode: str = "LIVE"

class IngestMetricsResponse(BaseModel):
    events_received: int
    events_accepted: int
    events_rejected: int
    rate_limit_rejections: int
    auth_failures: int
    last_event_timestamp: Optional[str] = None
    rate_limit_per_minute: int
