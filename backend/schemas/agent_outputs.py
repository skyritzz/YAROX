"""
Schemas every agent's LLM output must satisfy before it is used.

These are deliberately permissive about *types* an LLM plausibly emits (strings for
identifiers, optional fields) and strict about *structure*. Semantic validation —
evidence citations must exist in the case, MITRE IDs must exist in the knowledge base —
happens afterwards in agents/evidence.py, because only the investigation knows them.
"""
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class LLMFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    finding: str
    kind: Optional[str] = None
    evidence_ids: List[str] = Field(default_factory=list)
    reasoning_summary: Optional[str] = None
    mitre_techniques: List[str] = Field(default_factory=list)
    confidence: Optional[float] = None


class TriageLLMOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    severity: str
    summary: str
    priority_score: Optional[float] = None
    findings: List[LLMFinding] = Field(default_factory=list)


class TimelineEntryLLM(BaseModel):
    model_config = ConfigDict(extra="ignore")

    time: Optional[str] = None
    action: str
    details: Optional[str] = None
    evidence_ids: List[str] = Field(default_factory=list)


class TimelineLLMOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    timeline: List[TimelineEntryLLM] = Field(default_factory=list)
    findings: List[LLMFinding] = Field(default_factory=list)


class MitreMappingLLM(BaseModel):
    model_config = ConfigDict(extra="ignore")

    technique_id: str
    technique_name: Optional[str] = None
    tactic: Optional[str] = None
    reason: Optional[str] = None
    evidence_ids: List[str] = Field(default_factory=list)


class ThreatIntelLLMOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    mitre_mapping: List[MitreMappingLLM] = Field(default_factory=list)
    historical_insight: Optional[str] = None
    findings: List[LLMFinding] = Field(default_factory=list)


class RecommendationLLM(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action: str
    rationale: Optional[str] = None
    evidence_ids: List[str] = Field(default_factory=list)


class ReportLLMOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    executive_summary: str = Field(..., min_length=1)
    recommendations: List[RecommendationLLM] = Field(default_factory=list)
    findings: List[LLMFinding] = Field(default_factory=list)
