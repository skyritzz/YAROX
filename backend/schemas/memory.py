from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Any, Dict, Union
from datetime import datetime

class InvestigationMetadata(BaseModel):
    investigation_id: str
    created_at: datetime
    qdrant_id: str
    knowledge_version: int = 1
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    # Knowledge is assembled deterministically from persisted case data; no LLM is used
    llm_model: Optional[str] = None
    generated_at: datetime
    generation_prompt_version: str = "1.0"
    # "investigation_report": built from the current persisted report;
    # "case_evidence": the case has no report, built from evidence and detection data only
    knowledge_source: str = "investigation_report"
    source_report_id: Optional[str] = None
    source_report_version: Optional[int] = None
    # Exact text embedded into the vector store (kept so indexing can be retried from the stored record)
    embedding_text: str = ""

class InvestigationSection(BaseModel):
    title: str
    summary: str
    executive_summary: Optional[str] = None
    severity: str
    risk_score: float

class AttackSection(BaseModel):
    attack_type: Optional[str] = None
    malware_family: Optional[str] = None
    campaign: Optional[str] = None
    mitre_techniques: List[str] = Field(default_factory=list)
    kill_chain: List[str] = Field(default_factory=list)

class EvidenceSection(BaseModel):
    ips: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)
    filenames: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    hosts: List[str] = Field(default_factory=list)
    processes: List[str] = Field(default_factory=list)
    registry_keys: List[str] = Field(default_factory=list)
    commands: List[str] = Field(default_factory=list)

class TimelineEvent(BaseModel):
    time: Optional[str] = None
    action: Optional[str] = None
    details: Optional[str] = None
    description: Optional[str] = None
    event: Optional[str] = None
    timestamp: Optional[str] = None

    def is_empty(self) -> bool:
        """Returns True if every field is None (no meaningful data)."""
        return all(
            v is None for v in (
                self.time, self.action, self.details,
                self.description, self.event, self.timestamp
            )
        )

class TimelineSection(BaseModel):
    important_events: List[Union[TimelineEvent, str]] = Field(default_factory=list)
    attack_story: Optional[str] = None

    @field_validator("important_events", mode="before")
    @classmethod
    def validate_event_items(cls, v: Any) -> list:
        """Strict validation: reject non-str/non-dict items and dicts that
        produce completely empty TimelineEvents."""
        if not isinstance(v, list):
            raise ValueError("important_events must be a list")
        validated = []
        for i, item in enumerate(v):
            if isinstance(item, str):
                validated.append(item)
            elif isinstance(item, dict):
                te = TimelineEvent(**item)
                if te.is_empty():
                    raise ValueError(
                        f"important_events[{i}]: dict {item!r} produced an "
                        f"empty TimelineEvent (no recognized fields). "
                        f"Accepted fields: time, action, details, description, event, timestamp."
                    )
                validated.append(te)
            elif isinstance(item, TimelineEvent):
                if item.is_empty():
                    raise ValueError(
                        f"important_events[{i}]: TimelineEvent has no populated fields."
                    )
                validated.append(item)
            else:
                raise ValueError(
                    f"important_events[{i}]: unsupported type {type(item).__name__!r}. "
                    f"Each event must be a string or a dict with recognized TimelineEvent fields."
                )
        return validated

class RecommendationsSection(BaseModel):
    immediate_actions: List[str] = Field(default_factory=list)
    long_term_actions: List[str] = Field(default_factory=list)

class InvestigationKnowledgeObject(BaseModel):
    investigation: InvestigationSection
    attack: AttackSection
    evidence: EvidenceSection
    timeline: TimelineSection
    recommendations: RecommendationsSection
    lessons_learned: Optional[str] = None
    metadata: InvestigationMetadata

class InvestigationFingerprint(BaseModel):
    attack_type: Optional[str] = None
    mitre_techniques: List[str] = Field(default_factory=list)
    campaign: Optional[str] = None
    risk_score: float = 0.0
    # SHA-256 over sorted IOCs; None when the case has no IOCs (an empty set is not a match)
    ioc_hash: Optional[str] = None
    timeline_hash: str = ""

class SimilarityResult(BaseModel):
    investigation_id: str
    similarity_score: float
    semantic_score: float = 0.0
    mitre_overlap_score: float = 0.0
    ioc_overlap_score: float = 0.0
    asset_overlap_score: float = 0.0
    attack_type_match: bool = False
    campaign_match: bool = False
    shared_mitre_techniques: List[str] = Field(default_factory=list)
    shared_iocs: List[str] = Field(default_factory=list)
    shared_assets: List[str] = Field(default_factory=list)
    knowledge_object: Optional[InvestigationKnowledgeObject] = None

class MemoryContext(BaseModel):
    top_similar_cases: List[SimilarityResult] = Field(default_factory=list)
    shared_mitre_techniques: List[str] = Field(default_factory=list)
    shared_iocs: List[str] = Field(default_factory=list)
    shared_assets: List[str] = Field(default_factory=list)
    shared_campaigns: List[str] = Field(default_factory=list)
    previous_resolutions: List[str] = Field(default_factory=list)
    previous_recommendations: List[str] = Field(default_factory=list)
    confidence_score: float = 0.0
