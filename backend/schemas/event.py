from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime
import uuid

class EventResponse(BaseModel):
    id: uuid.UUID
    timestamp: datetime
    hostname: Optional[str]
    user_name: Optional[str]
    source: str
    event_type: str
    severity: str
    raw_log: Dict[str, Any]
    metadata_: Optional[Dict[str, Any]]

    class Config:
        from_attributes = True

class InvestigationEvent(BaseModel):
    event_id: str
    investigation_id: str
    execution_id: str
    timestamp: str
    agent_name: str
    event_type: str  # e.g., "reasoning_step", "tool_call"
    step_type: str   # dynamic mapped step types
    payload: Dict[str, Any]
    confidence: Optional[float] = None
    evidence_ids: list[str] = []
    tool_call_id: Optional[str] = None
