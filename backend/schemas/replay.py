from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime
import uuid

ALLOWED_SCENARIOS = {'apt29_simulation', 'apt_blackout', 'credential_theft', 'insider_threat'}

class ReplayStartRequest(BaseModel):
    scenario_name: str = Field(..., description="Name of the attack scenario to simulate")
    speed_multiplier: float = Field(1.0, ge=0.1, le=100.0, description="Simulation speed multiplier (0.1x to 100x)")

    @field_validator('scenario_name')
    @classmethod
    def validate_scenario(cls, v: str) -> str:
        clean_name = v.strip().lower()
        if clean_name not in ALLOWED_SCENARIOS:
            raise ValueError(f"Unknown scenario: '{v}'. Allowed scenarios: {sorted(list(ALLOWED_SCENARIOS))}")
        return clean_name

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
