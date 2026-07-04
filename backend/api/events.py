from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
import uuid
from typing import List

from database.session import get_db
from models.event import Event
from schemas.event import EventResponse

router = APIRouter()

@router.get("", response_model=List[EventResponse])
async def get_events(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: str = Query(None),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Event).order_by(desc(Event.timestamp))
    if severity:
        stmt = stmt.where(Event.severity == severity.upper())
    
    stmt = stmt.limit(limit).offset(offset)
    result = await db.execute(stmt)
    return result.scalars().all()

@router.get("/{event_id}", response_model=EventResponse)
async def get_event(event_id: str, db: AsyncSession = Depends(get_db)):
    try:
        uid = uuid.UUID(event_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")
        
    result = await db.execute(select(Event).where(Event.id == uid))
    event = result.scalars().first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
