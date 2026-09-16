from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import uuid
import asyncio
from typing import List

from database.session import get_db
from models.replay import ReplaySession
from models.user import User
from schemas.replay import ReplayStartRequest, ReplaySessionResponse
from replay.engine import ReplayEngine
from core.events import event_bus
from core.auth import require_analyst_or_admin, require_authenticated

router = APIRouter()

active_engines = {}

def validate_uuid(id_str: str) -> uuid.UUID:
    try:
        return uuid.UUID(id_str)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID format: {id_str}"
        )

async def run_replay_task(engine: ReplayEngine, scenario_name: str, session_id: str):
    try:
        await engine.stream_events(scenario_name, session_id)
    except Exception as e:
        print(f"Replay task failed: {e}")
        engine.is_playing = False
        from database.session import AsyncSessionLocal
        from models.replay import ReplaySession
        import uuid
        async with AsyncSessionLocal() as db:
            try:
                db_session = await db.get(ReplaySession, uuid.UUID(session_id))
                if db_session:
                    db_session.status = "FAILED"
                    await db.commit()
            except Exception:
                pass

@router.post("/start", response_model=ReplaySessionResponse)
async def start_replay(
    request: ReplayStartRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_analyst_or_admin),
    db: AsyncSession = Depends(get_db)
):
    session_record = ReplaySession(
        scenario_name=request.scenario_name,
        status="PLAYING",
        speed_multiplier=request.speed_multiplier
    )
    db.add(session_record)
    await db.commit()
    await db.refresh(session_record)

    engine = ReplayEngine(event_bus)
    engine.speed_multiplier = request.speed_multiplier
    active_engines[str(session_record.id)] = engine
    
    background_tasks.add_task(run_replay_task, engine, request.scenario_name, str(session_record.id))

    return session_record

@router.post("/{session_id}/pause")
async def pause_replay(
    session_id: str,
    current_user: User = Depends(require_analyst_or_admin),
    db: AsyncSession = Depends(get_db)
):
    session_uuid = validate_uuid(session_id)
    engine = active_engines.get(session_id)
    if engine:
        engine.is_playing = False
        await event_bus.publish("ReplayPaused", {"session_id": session_id})
        
    result = await db.execute(select(ReplaySession).where(ReplaySession.id == session_uuid))
    session_record = result.scalars().first()
    if session_record:
        session_record.status = "PAUSED"
        await db.commit()
        return {"status": "paused", "session_id": session_id}
    
    raise HTTPException(status_code=404, detail="Session not found")

@router.post("/{session_id}/reset")
async def reset_replay(
    session_id: str,
    current_user: User = Depends(require_analyst_or_admin),
    db: AsyncSession = Depends(get_db)
):
    session_uuid = validate_uuid(session_id)
    engine = active_engines.get(session_id)
    if engine:
        engine.is_playing = False
        if session_id in active_engines:
            del active_engines[session_id]

    result = await db.execute(select(ReplaySession).where(ReplaySession.id == session_uuid))
    session_record = result.scalars().first()
    if session_record:
        session_record.status = "FINISHED"
        await db.commit()

    return {"status": "reset", "session_id": session_id}

@router.get("/status", response_model=List[ReplaySessionResponse])
async def get_status(
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(ReplaySession).order_by(ReplaySession.created_at.desc()))
    return result.scalars().all()
