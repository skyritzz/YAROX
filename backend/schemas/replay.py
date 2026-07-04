from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import uuid

class ReplayStartRequest(BaseModel):
    scenario_name: str
    speed_multiplier: float = 1.0

class ReplaySessionResponse(BaseModel):
    id: uuid.UUID
    scenario_name: str
    status: str
    speed_multiplier: float
    current_index: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
