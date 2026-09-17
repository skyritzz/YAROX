import asyncio
from core.events import event_bus
from database.session import AsyncSessionLocal
from models.event import Event
from detection.engine import detection_engine
from services.investigation_runner import run_investigation_in_background
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
                    # The runner owns its own session and takes the per-case lock; a second
                    # detection for a case already under investigation records a re-run request
                    # instead of starting a duplicate run.
                    asyncio.create_task(run_investigation_in_background(str(case.id)))
        except Exception as e:
            print(f"Error in detection consumer: {e}")

def register_detection_consumers():
    event_bus.subscribe("EventStored", handle_event_stored)
