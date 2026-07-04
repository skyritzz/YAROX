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
