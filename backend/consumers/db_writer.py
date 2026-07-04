import asyncio
from core.events import event_bus
from database.session import AsyncSessionLocal
from models.event import Event
from typing import Dict, Any

async def handle_event_normalized(data: Dict[str, Any]):
    """
    Subscribes to 'EventNormalized' topic.
    Receives normalized event data (dict) and writes it to the Evidence Store (Database).
    """
    async with AsyncSessionLocal() as session:
        try:
            db_event = Event(**data)
            session.add(db_event)
            await session.commit()
            await session.refresh(db_event)
            await event_bus.publish("EventStored", {"id": str(db_event.id)})
        except Exception as e:
            print(f"Error storing event: {e}")

def register_consumers():
    event_bus.subscribe("EventNormalized", handle_event_normalized)
