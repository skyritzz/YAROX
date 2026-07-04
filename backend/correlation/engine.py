from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models.investigation import InvestigationCase, InvestigationStatus, EvidenceItem
from models.event import Event
from datetime import datetime, timezone, timedelta

class CorrelationEngine:
    async def find_related_case(self, db: AsyncSession, event: Event, technique_name: str) -> InvestigationCase | None:
        """
        Finds an existing open case to correlate the event with, based on technique and entities (user/host).
        """
        time_threshold = datetime.now(timezone.utc) - timedelta(hours=24)
        
        # Build the condition for entity matching
        entity_conditions = []
        if event.user_name:
            entity_conditions.append(Event.user_name == event.user_name)
        if event.hostname:
            entity_conditions.append(Event.hostname == event.hostname)
            
        if not entity_conditions:
            return None # Cannot correlate without an entity
            
        from sqlalchemy import or_
        entity_clause = or_(*entity_conditions)

        result = await db.execute(
            select(InvestigationCase)
            .join(EvidenceItem, InvestigationCase.id == EvidenceItem.case_id)
            .join(Event, EvidenceItem.event_id == Event.id)
            .where(
                InvestigationCase.status.in_([
                    InvestigationStatus.OPEN, 
                    InvestigationStatus.ANALYZING
                ]),
                InvestigationCase.title == f"Automated Detection: {technique_name}",
                InvestigationCase.updated_at >= time_threshold
            )
            .where(entity_clause)
            .order_by(InvestigationCase.updated_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

correlation_engine = CorrelationEngine()
