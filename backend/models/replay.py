import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Float
from sqlalchemy.dialects.postgresql import UUID
from models.base import Base

class ReplaySession(Base):
    __tablename__ = "replay_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scenario_name = Column(String, index=True, nullable=False)
    status = Column(String, default="INITIALIZED") # INITIALIZED, PLAYING, PAUSED, FINISHED, ERROR
    speed_multiplier = Column(Float, default=1.0)
    current_index = Column(String, nullable=True) # ID of last processed event or dataset index
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
