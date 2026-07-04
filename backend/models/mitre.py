import uuid
from sqlalchemy import Column, String, Float, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from models.base import Base

class AttackTechnique(Base):
    __tablename__ = "attack_techniques"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("investigation_cases.id"), nullable=False, index=True)
    
    technique_id = Column(String, nullable=False, index=True)
    technique_name = Column(String, nullable=False)
    tactic = Column(String, nullable=False, index=True)
    confidence = Column(Float, nullable=False, default=1.0)
    reason = Column(Text, nullable=True)
    
    case = relationship("InvestigationCase", back_populates="mitre_techniques")
