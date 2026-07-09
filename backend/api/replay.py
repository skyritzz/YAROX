from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import uuid
import asyncio

from database.session import get_db
from models.replay import ReplaySession
from schemas.replay import ReplayStartRequest, ReplaySessionResponse
from replay.engine import ReplayEngine
from core.events import event_bus

router = APIRouter()

# Global dict to store running engines for simplicity in Phase 1
active_engines = {}

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
async def start_replay(request: ReplayStartRequest, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    # Create DB record
    session_record = ReplaySession(
        scenario_name=request.scenario_name,
        status="PLAYING",
        speed_multiplier=request.speed_multiplier
    )
    db.add(session_record)
    await db.commit()
    await db.refresh(session_record)

    # Start engine (Notice we pass event_bus now, not db session)
    engine = ReplayEngine(event_bus)
    engine.speed_multiplier = request.speed_multiplier
    active_engines[str(session_record.id)] = engine
    
    background_tasks.add_task(run_replay_task, engine, request.scenario_name, str(session_record.id))

    return session_record

@router.post("/{session_id}/pause")
async def pause_replay(session_id: str, db: AsyncSession = Depends(get_db)):
    engine = active_engines.get(session_id)
    if engine:
        engine.is_playing = False
        await event_bus.publish("ReplayPaused", {"session_id": session_id})
        
    # Update DB
    result = await db.execute(select(ReplaySession).where(ReplaySession.id == uuid.UUID(session_id)))
    session_record = result.scalars().first()
    if session_record:
        session_record.status = "PAUSED"
        await db.commit()
        return {"status": "paused"}
    
    raise HTTPException(status_code=404, detail="Session not found")

@router.post("/{session_id}/reset")
async def reset_replay(session_id: str, db: AsyncSession = Depends(get_db)):
    engine = active_engines.get(session_id)
    if engine:
        engine.is_playing = False
        del active_engines[session_id]

    # Delete session and events for simplicity in this reset
    result = await db.execute(select(ReplaySession).where(ReplaySession.id == uuid.UUID(session_id)))
    session_record = result.scalars().first()
    if session_record:
        session_record.status = "FINISHED"
        await db.commit()

    return {"status": "reset"}

@router.get("/status", response_model=list[ReplaySessionResponse])
async def get_status(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ReplaySession).order_by(ReplaySession.created_at.desc()))
    return result.scalars().all()
