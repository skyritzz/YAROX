from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid
from models.investigation import Severity, InvestigationStatus

class CaseNoteUserResponse(BaseModel):
    id: uuid.UUID
    email: str
    full_name: Optional[str] = None
    role: str

    class Config:
        from_attributes = True

class CaseNoteCreate(BaseModel):
    content: str = Field(..., min_length=1)

    @field_validator("content")
    @classmethod
    def validate_content_not_empty(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Note content cannot be empty or only whitespace")
        return cleaned

class CaseNoteResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    user_id: uuid.UUID
    content: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    user: Optional[CaseNoteUserResponse] = None

    class Config:
        from_attributes = True

class CaseAssignRequest(BaseModel):
    assigned_to_user_id: Optional[uuid.UUID] = None

class CaseAssignResponse(BaseModel):
    id: uuid.UUID
    assigned_to_user_id: Optional[uuid.UUID] = None
    message: str

class SeverityOverrideRequest(BaseModel):
    severity: Severity
    reason: str = Field(..., min_length=1)

    @field_validator("reason")
    @classmethod
    def validate_reason_not_empty(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Reason cannot be empty or only whitespace")
        return cleaned

class SeverityOverrideResponse(BaseModel):
    id: uuid.UUID
    previous_severity: str
    severity: str
    reason: str

class CaseReopenRequest(BaseModel):
    reason: Optional[str] = None

class CaseReopenResponse(BaseModel):
    id: uuid.UUID
    status: str
    message: str

class AuditLogUserResponse(BaseModel):
    id: uuid.UUID
    email: str
    full_name: Optional[str] = None
    role: str

    class Config:
        from_attributes = True

class AuditLogResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    user_id: Optional[uuid.UUID] = None
    action: str
    details: Dict[str, Any]
    timestamp: datetime
    user: Optional[AuditLogUserResponse] = None

    class Config:
        from_attributes = True
