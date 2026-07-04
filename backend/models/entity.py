import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import enum

from models.base import Base

class EntityType(str, enum.Enum):
    USER = "USER"
    HOST = "HOST"
    PROCESS = "PROCESS"
    IP = "IP"
    FILE = "FILE"

class SecurityEntity(Base):
    __tablename__ = "security_entities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type = Column(Enum(EntityType), nullable=False, index=True)
    name = Column(String, nullable=False, index=True) # e.g. 'jdoe', 'WIN-001', 'powershell.exe'
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class SecurityRelationship(Base):
    __tablename__ = "security_relationships"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id = Column(UUID(as_uuid=True), ForeignKey("security_entities.id"), nullable=False)
    target_id = Column(UUID(as_uuid=True), ForeignKey("security_entities.id"), nullable=False)
    action = Column(String, nullable=False) # e.g. 'logged into', 'executed'
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation_cases.id"), nullable=True, index=True)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    source = relationship("SecurityEntity", foreign_keys=[source_id])
    target = relationship("SecurityEntity", foreign_keys=[target_id])
