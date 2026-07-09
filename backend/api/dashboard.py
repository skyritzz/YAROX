from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, desc
from datetime import datetime, timezone

from database.session import get_db
from models.event import Event
from models.replay import ReplaySession

router = APIRouter()

@router.get("/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    # Total events
    total_events_result = await db.execute(select(func.count(Event.id)))
    total_events = total_events_result.scalar() or 0

    # Severity breakdown
    severity_result = await db.execute(select(Event.severity, func.count(Event.id)).group_by(Event.severity))
    severities = {row[0]: row[1] for row in severity_result.all()}

    # Replay status
    replay_result = await db.execute(select(ReplaySession).order_by(ReplaySession.created_at.desc()).limit(1))
    latest_session = replay_result.scalars().first()
    
    # Calculate Elapsed and Progress (Mock logic based on total events for now)
    elapsed_seconds = 0
    progress_percent = 0
    events_per_sec = 0
    
    if latest_session:
        now = datetime.now(timezone.utc)
        elapsed_seconds = max(0, int((now - latest_session.created_at).total_seconds()))
        
        if latest_session.current_index and '/' in latest_session.current_index:
            try:
                curr, tot = map(int, latest_session.current_index.split('/'))
                progress_percent = min(100, int((curr / tot) * 100)) if tot > 0 else 0
            except Exception:
                pass
                
        if elapsed_seconds > 0 and latest_session.current_index:
            try:
                curr = int(latest_session.current_index.split('/')[0])
                events_per_sec = round(curr / elapsed_seconds, 1)
            except Exception:
                pass
            
    # Recent Activity (Merge recent events and session updates)
    activity_feed = []
    if latest_session:
        activity_feed.append({
            "timestamp": latest_session.created_at.isoformat(),
            "message": f"Replay Started ({latest_session.scenario_name}) - Speed: {latest_session.speed_multiplier}x"
        })
    
    from models.investigation import AgentAction
    
    recent_actions_result = await db.execute(select(AgentAction).order_by(desc(AgentAction.created_at)).limit(15))
    recent_actions = recent_actions_result.scalars().all()
    for action in recent_actions:
        # Some agent actions might have empty string or just thought
        msg = action.thought or action.action_taken or "Analyzing data"
        if len(msg) > 120:
            msg = msg[:120] + "..."
            
        activity_feed.append({
            "timestamp": action.created_at.isoformat(),
            "message": msg,
            "agent_name": action.agent_name
        })
        
    # Sort activity descending
    activity_feed.sort(key=lambda x: x["timestamp"], reverse=True)
    
    # Average Detection Confidence
    from models.investigation import InvestigationCase
    confidence_result = await db.execute(select(func.avg(InvestigationCase.confidence_score)))
    avg_confidence = confidence_result.scalar() or 0.0
    
    return {
        "total_events": total_events,
        "events_per_sec": events_per_sec,
        "severities": severities,
        "average_confidence": round(avg_confidence * 100),
        "system_status": "ONLINE",
        "active_scenario": latest_session.scenario_name if latest_session else "None",
        "replay_status": latest_session.status if latest_session else "IDLE",
        "replay_speed": latest_session.speed_multiplier if latest_session else 1.0,
        "elapsed_seconds": elapsed_seconds,
        "progress_percent": progress_percent,
        "recent_activity": activity_feed[:6]
    }
