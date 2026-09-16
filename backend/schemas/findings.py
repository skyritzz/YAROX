"""
Agent evidence contract.

Every agent conclusion is expressed as an ``AgentFindingRecord``. A finding is only
accepted when every evidence ID it cites belongs to the investigation being analyzed.
Findings do not contain chain-of-thought; ``reasoning_summary`` is a short, auditable
justification.
"""
import uuid
from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, Field

FindingKind = Literal["observation", "hypothesis"]

MAX_FINDING_CHARS = 1000
MAX_REASONING_CHARS = 500


class AgentFindingRecord(BaseModel):
    finding_id: uuid.UUID
    agent: str
    finding: str = Field(..., min_length=1, max_length=MAX_FINDING_CHARS)
    kind: FindingKind
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    evidence_ids: List[uuid.UUID] = Field(..., min_length=1)
    reasoning_summary: str = Field("", max_length=MAX_REASONING_CHARS)
    mitre_techniques: List[str] = Field(default_factory=list)
    timestamp: datetime


class RejectedFinding(BaseModel):
    agent: str
    reason: str
    submitted: dict


class EvidenceCitation(BaseModel):
    evidence_id: uuid.UUID
    evidence_type: str
    artifact: Optional[str]
    source: str
    timestamp: datetime
    event_id: Optional[uuid.UUID]
    event_source: Optional[str]
    event_timestamp: Optional[datetime]
    event_payload_sha256: Optional[str]


class TracedFinding(BaseModel):
    finding_id: uuid.UUID
    agent: str
    finding: str
    kind: FindingKind
    confidence: Optional[float]
    reasoning_summary: Optional[str]
    mitre_techniques: List[str]
    execution_id: uuid.UUID
    timestamp: datetime
    evidence: List[EvidenceCitation]
