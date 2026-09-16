from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
import uuid
from typing import List, Optional

from database.session import get_db
from models.event import Event
from models.user import User
from schemas.event import EventResponse
from core.auth import require_authenticated

router = APIRouter()

@router.get("", response_model=List[EventResponse])
async def get_events(
    limit: int = Query(50, ge=1, le=1000, description="Page limit (1-1000)"),
    offset: int = Query(0, ge=0, description="Page offset"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Event).order_by(desc(Event.timestamp))
    if severity:
        stmt = stmt.where(Event.severity == severity.strip().upper())
    
    stmt = stmt.limit(limit).offset(offset)
    result = await db.execute(stmt)
    return result.scalars().all()

@router.get("/{event_id}", response_model=EventResponse)
async def get_event(
    event_id: str,
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db)
):
    try:
        uid = uuid.UUID(event_id)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid UUID format")
        
    result = await db.execute(select(Event).where(Event.id == uid))
    event = result.scalars().first()
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return event
