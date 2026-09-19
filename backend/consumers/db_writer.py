import logging
from typing import Any, Dict

import dateutil.parser

from core.events import event_bus
from core.integrity import compute_event_hash
from database.session import AsyncSessionLocal
from models.event import Event

logger = logging.getLogger("yarox.events")


def _deserialize(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    The in-memory bus hands subscribers the original Python objects; the durable
    Redis Streams bus hands them the result of json.loads(json.dumps(data, default=str)) -
    timestamp survives that round trip as a string, not a datetime, which both
    core.integrity.compute_event_hash and the Event ORM column require. Coerce it
    back here, at the one place both bus implementations converge.
    """
    timestamp = data.get("timestamp")
    if isinstance(timestamp, str):
        data = dict(data, timestamp=dateutil.parser.isoparse(timestamp))
    return data


async def handle_event_normalized(data: Dict[str, Any]):
    """
    Subscribes to 'EventNormalized' topic.
    Receives normalized event data (dict) and writes it to the Evidence Store (Database).
    Re-raises on failure so the durable bus leaves the entry unacknowledged for retry
    (see core.events.RedisStreamEventBus._process) instead of silently dropping the event.
    """
    data = _deserialize(data)
    async with AsyncSessionLocal() as session:
        db_event = Event(**data, payload_sha256=compute_event_hash(data))
        session.add(db_event)
        await session.commit()
        await session.refresh(db_event)
        await event_bus.publish("EventStored", {"id": str(db_event.id)})

def register_consumers():
    event_bus.subscribe("EventNormalized", handle_event_normalized)
