import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from models.base import Base

class Event(Base):
    __tablename__ = "events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    hostname = Column(String, index=True, nullable=True)
    user_name = Column(String, index=True, nullable=True)  # user is a reserved keyword in some DBs
    source = Column(String, index=True, nullable=False) # e.g., Windows Event Log, Suricata
    event_type = Column(String, index=True, nullable=False) # e.g., Login Failed, Process Create
    severity = Column(String, index=True, nullable=False) # INFO, LOW, MEDIUM, HIGH, CRITICAL
    raw_log = Column(JSONB, nullable=False)
    metadata_ = Column("metadata", JSONB, nullable=True) # metadata is used by sqlalchemy internally, so we alias it
