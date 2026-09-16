from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import or_, and_
from models.investigation import InvestigationCase, InvestigationStatus, EvidenceItem
from models.event import Event
from datetime import datetime, timezone, timedelta

class CorrelationEngine:
    """
    Contextual Multi-Stage Correlation Engine.
    Correlates incoming security events with existing active investigation cases
    based on entity graph overlap (User, Host, IP), temporal proximity, and active case status,
    allowing multi-stage attacks across different MITRE tactics to merge into unified cases.
    """
    async def find_related_case(self, db: AsyncSession, event: Event, technique_name: str = "") -> InvestigationCase | None:
        """
        Finds an existing open/analyzing case to correlate the event with based on entity graph and temporal proximity.
        """
        time_threshold = datetime.now(timezone.utc) - timedelta(hours=24)
        
        # 1. Build entity conditions (excluding placeholder values)
        entity_conditions = []
        if event.user_name and event.user_name.strip().lower() not in ("unknown", "system", "anonymous", ""):
            entity_conditions.append(Event.user_name == event.user_name)
        if event.hostname and event.hostname.strip().lower() not in ("unknown", ""):
            entity_conditions.append(Event.hostname == event.hostname)
            
        if not entity_conditions:
            return None # Cannot correlate safely without a specific entity
            
        entity_clause = or_(*entity_conditions)

        # 2. Query for active cases that share any evidence entity within the 24-hour active window
        result = await db.execute(
            select(InvestigationCase)
            .join(EvidenceItem, InvestigationCase.id == EvidenceItem.case_id)
            .join(Event, EvidenceItem.event_id == Event.id)
            .where(
                InvestigationCase.status.in_([
                    InvestigationStatus.OPEN, 
                    InvestigationStatus.ANALYZING
                ]),
                InvestigationCase.updated_at >= time_threshold
            )
            .where(entity_clause)
            .order_by(InvestigationCase.updated_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

correlation_engine = CorrelationEngine()
