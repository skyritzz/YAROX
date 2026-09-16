import json
import asyncio
from typing import List, Dict, Any
import os
import dateutil.parser
from core.events import EventBus
from plugins.parsers.generic import GenericJSONParser

class ReplayEngine:
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self.parser = GenericJSONParser()
        self.is_playing = False
        self.speed_multiplier = 1.0

    async def load_dataset(self, scenario_name: str) -> List[Dict[str, Any]]:
        # Map scenario name to path
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../datasets"))
        file_path = os.path.join(base_path, scenario_name, "events.json")
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Dataset {scenario_name} not found at {file_path}")
            
        with open(file_path, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return data.get("events", [])

    async def stream_events(self, scenario_name: str, session_id: str):
        self.is_playing = True
        
        await self.event_bus.publish("ReplayStarted", {"session_id": session_id, "scenario": scenario_name})

        events_data = await self.load_dataset(scenario_name)
        
        if not events_data:
            self.is_playing = False
            await self.event_bus.publish("ReplayCompleted", {"session_id": session_id})
            return

        total_events = len(events_data)

        # Sort events by timestamp just in case
        events_data.sort(key=lambda x: dateutil.parser.isoparse(x["timestamp"]))

        prev_time = None
        from database.session import AsyncSessionLocal
        from models.replay import ReplaySession

        for i, raw_event in enumerate(events_data):
            if not self.is_playing:
                await self.event_bus.publish("ReplayPaused", {"session_id": session_id})
                break

            current_time = dateutil.parser.isoparse(raw_event["timestamp"])
            
            if prev_time is not None:
                delta = (current_time - prev_time).total_seconds()
                sleep_time = max(0, delta / self.speed_multiplier)
                
                # Smart Fast-Forward: If the gap between events is too large, cap the real-world sleep time
                # so the simulation doesn't appear frozen (e.g. waiting 30 mins for a 5-hour dataset gap at 10x)
                if sleep_time > 1.0:
                    sleep_time = 1.0
                    
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)

            # Parse and Publish
            parsed_data = self.parser.parse(raw_event)
            await self.event_bus.publish("EventNormalized", parsed_data)
            
            # Throttle database progress updates to prevent massive I/O bottlenecks during fast replays
            if i % 10 == 0 or i == total_events - 1:
                async with AsyncSessionLocal() as db:
                    import uuid
                    try:
                        db_session = await db.get(ReplaySession, uuid.UUID(session_id))
                        if db_session:
                            db_session.current_index = f"{i+1}/{total_events}"
                            await db.commit()
                    except Exception as e:
                        print("Error updating session progress:", e)

            prev_time = current_time

        if self.is_playing:
            self.is_playing = False
            async with AsyncSessionLocal() as db:
                import uuid
                try:
                    db_session = await db.get(ReplaySession, uuid.UUID(session_id))
                    if db_session:
                        db_session.status = "FINISHED"
                        db_session.current_index = f"{total_events}/{total_events}"
                        await db.commit()
                except Exception:
                    pass
            await self.event_bus.publish("ReplayCompleted", {"session_id": session_id})
