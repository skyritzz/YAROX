import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Float, ForeignKey, Enum, Text
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
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    evidence_items = relationship("EvidenceItem", back_populates="case", cascade="all, delete-orphan")
    agent_actions = relationship("AgentAction", back_populates="case", cascade="all, delete-orphan")
    mitre_techniques = relationship("AttackTechnique", back_populates="case", cascade="all, delete-orphan")

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
    
    case = relationship("InvestigationCase", back_populates="evidence_items")
    event = relationship("Event")

class AgentAction(Base):
    __tablename__ = "agent_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation_cases.id"), nullable=False, index=True)
    
    agent_name = Column(String, nullable=False, index=True)
    thought = Column(Text, nullable=True)
    action_taken = Column(String, nullable=True)
    
    input_data = Column(JSONB, nullable=True)
    output_data = Column(JSONB, nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    case = relationship("InvestigationCase", back_populates="agent_actions")
