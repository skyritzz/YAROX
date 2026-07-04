import asyncio
from core.events import event_bus
from database.session import AsyncSessionLocal
from models.event import Event
from detection.engine import detection_engine
from agents.orchestrator import orchestrator
from typing import Dict, Any

async def handle_event_stored(data: Dict[str, Any]):
    event_id = data.get("id")
    if not event_id:
        return

    async with AsyncSessionLocal() as session:
        try:
            event = await session.get(Event, event_id)
            if event:
                case = await detection_engine.process_event(session, event)
                if case:
                    async def _run_bg(cid: str):
                        async with AsyncSessionLocal() as bg_session:
                            await orchestrator.run_investigation(bg_session, cid)
                    asyncio.create_task(_run_bg(str(case.id)))
        except Exception as e:
            print(f"Error in detection consumer: {e}")

def register_detection_consumers():
    event_bus.subscribe("EventStored", handle_event_stored)
