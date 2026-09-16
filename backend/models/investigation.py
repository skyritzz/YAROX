import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Float, ForeignKey, Enum, Text, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import enum

from models.base import Base

class InvestigationStatus(str, enum.Enum):
    OPEN = "OPEN"
    ANALYZING = "ANALYZING"
    WAITING_FOR_REVIEW = "WAITING_FOR_REVIEW"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

class Severity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class InvestigationCase(Base):
    __tablename__ = "investigation_cases"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(Enum(InvestigationStatus), default=InvestigationStatus.OPEN, index=True)
    severity = Column(Enum(Severity), default=Severity.MEDIUM, index=True)
    confidence_score = Column(Float, nullable=True)
    confidence_breakdown = Column(JSONB, nullable=True)
    
    # Phase 5.1 Case Management & Attribution
    assigned_to_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    resolved_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    evidence_items = relationship("EvidenceItem", back_populates="case", cascade="all, delete-orphan")
    agent_executions = relationship("AgentExecution", back_populates="case", cascade="all, delete-orphan")
    mitre_techniques = relationship("AttackTechnique", back_populates="case", cascade="all, delete-orphan")
    
    assigned_to = relationship("User", foreign_keys=[assigned_to_user_id])
    resolved_by = relationship("User", foreign_keys=[resolved_by_user_id])
    notes = relationship("CaseNote", back_populates="case", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="case", cascade="all, delete-orphan")

class EvidenceItem(Base):
    __tablename__ = "evidence_items"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation_cases.id"), nullable=False, index=True)
    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id"), nullable=True, index=True)
    
    evidence_type = Column(String, nullable=False)
    source = Column(String, nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    artifact = Column(String, nullable=True)
    
    reason = Column(Text, nullable=True)
    importance_score = Column(Float, default=0.5)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    related_agent = Column(String, nullable=True) # Name of the agent that found this
    
    case = relationship("InvestigationCase", back_populates="evidence_items")
    event = relationship("Event")

class AgentExecution(Base):
    __tablename__ = "agent_executions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigation_cases.id"), nullable=False, index=True)
    
    agent_name = Column(String, nullable=False, index=True)
    status = Column(String, default="running")
    confidence = Column(Float, nullable=True)
    
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Cached Metrics
    total_execution_time_ms = Column(Float, nullable=True)
    tool_execution_time_ms = Column(Float, nullable=True)
    llm_execution_time_ms = Column(Float, nullable=True)
    reasoning_step_count = Column(Integer, default=0)
    tool_call_count = Column(Integer, default=0)
    
    # Explanations
    confidence_explanation = Column(JSONB, nullable=True)
    
    case = relationship("InvestigationCase", back_populates="agent_executions")
    reasoning_steps = relationship("AgentReasoningStep", back_populates="execution", cascade="all, delete-orphan")
    tool_calls = relationship("AgentToolCall", back_populates="execution", cascade="all, delete-orphan")

class AgentReasoningStep(Base):
    __tablename__ = "agent_reasoning_steps"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    execution_id = Column(UUID(as_uuid=True), ForeignKey("agent_executions.id"), nullable=False, index=True)
    
    step_type = Column(String, nullable=False) # observation/tool/reasoning/decision/handoff/failed
    content = Column(JSONB, nullable=False)
    
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    execution = relationship("AgentExecution", back_populates="reasoning_steps")

class AgentToolCall(Base):
    __tablename__ = "agent_tool_calls"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    execution_id = Column(UUID(as_uuid=True), ForeignKey("agent_executions.id"), nullable=False, index=True)
    
    tool_name = Column(String, nullable=False)
    input = Column(JSONB, nullable=True)
    output = Column(JSONB, nullable=True)
    duration_ms = Column(Float, nullable=True)
    status = Column(String, nullable=True) # Running, Completed, Failed, Timeout, Cancelled, Cached
    
    execution = relationship("AgentExecution", back_populates="tool_calls")

class InvestigationMemory(Base):
    __tablename__ = "investigation_memory"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigation_cases.id"), index=True)
    
    # Versioning
    knowledge_version = Column(Integer, default=1)
    is_latest = Column(Boolean, default=True)
    
    # Domain Objects Stored as JSONB
    knowledge_object = Column(JSONB, nullable=False)
    fingerprint = Column(JSONB, nullable=False)
    
    # Provenance
    embedding_model = Column(String)
    llm_model = Column(String)
    generated_at = Column(DateTime(timezone=True))
    
    qdrant_id = Column(String, nullable=False)

    case = relationship("InvestigationCase", backref="memory")

class CaseNote(Base):
    __tablename__ = "case_notes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation_cases.id"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    content = Column(Text, nullable=False)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    case = relationship("InvestigationCase", back_populates="notes")
    user = relationship("User")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation_cases.id"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String, nullable=False, index=True)
    details = Column(JSONB, nullable=False, default=dict)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

    case = relationship("InvestigationCase", back_populates="audit_logs")
    user = relationship("User")

