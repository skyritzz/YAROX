from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query, status
from typing import List, Dict, Optional, Set
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from collections import defaultdict
import json
import uuid

from database.session import get_db, AsyncSessionLocal
from models.investigation import AgentReasoningStep, AgentExecution
from models.user import User
from core.auth import decode_access_token

router = APIRouter()

class ScopedConnectionManager:
    def __init__(self):
        # Maps case_id -> set of active WebSockets subscribed to this case
        self.case_rooms: Dict[str, Set[WebSocket]] = defaultdict(set)
        # Set of WebSockets subscribed globally (without specific case filter)
        self.global_subscribers: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket, user_id: str, case_id: Optional[str] = None):
        await websocket.accept()
        if case_id:
            self.case_rooms[str(case_id)].add(websocket)
        else:
            self.global_subscribers.add(websocket)

    def disconnect(self, websocket: WebSocket, case_id: Optional[str] = None):
        if case_id and str(case_id) in self.case_rooms:
            self.case_rooms[str(case_id)].discard(websocket)
            if not self.case_rooms[str(case_id)]:
                del self.case_rooms[str(case_id)]
        self.global_subscribers.discard(websocket)

    async def broadcast(self, message: dict):
        """
        Scoped broadcast: Detailed reasoning steps are sent ONLY to clients in the matching case room.
        Generic lifecycle alerts (e.g. REPORT_READY, AGENT_STARTED) are sent to the case room AND global listeners.
        """
        case_id = message.get("investigation_id") or message.get("case_id")
        event_type = message.get("event") or message.get("event_type")
        msg_text = json.dumps(message)

        recipients: Set[WebSocket] = set()
        
        if case_id:
            str_cid = str(case_id)
            if str_cid in self.case_rooms:
                recipients.update(self.case_rooms[str_cid])
                
        # High-level lifecycle events notify global dashboard subscribers too
        if event_type in ("REPORT_READY", "AGENT_STARTED", "AGENT_THINKING"):
            recipients.update(self.global_subscribers)

        # Send to all determined recipients
        stale_sockets = []
        for connection in recipients:
            try:
                await connection.send_text(msg_text)
            except Exception:
                stale_sockets.append(connection)
                
        # Clean up stale disconnected sockets
        for dead_ws in stale_sockets:
            if case_id and str(case_id) in self.case_rooms:
                self.case_rooms[str(case_id)].discard(dead_ws)
            self.global_subscribers.discard(dead_ws)

manager = ScopedConnectionManager()

@router.websocket("")
async def websocket_endpoint(
    websocket: WebSocket,
    case_id: Optional[str] = Query(None),
    token: Optional[str] = Query(None)
):
    # Priority 2: Enforce WebSocket Authentication
    if not token:
        # Check subprotocols or query
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Missing authentication token")
        return

    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if not user_id:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token payload")
            return
    except Exception:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Unauthorized")
        return

    # Validate case_id if provided
    if case_id:
        try:
            uuid.UUID(case_id)
        except (ValueError, TypeError):
            await websocket.close(code=status.WS_1003_UNSUPPORTED_DATA, reason="Invalid case_id UUID format")
            return

    await manager.connect(websocket, user_id=user_id, case_id=case_id)
    
    # Replay existing steps if case_id is provided
    if case_id:
        async with AsyncSessionLocal() as db:
            try:
                result = await db.execute(
                    select(AgentReasoningStep, AgentExecution.agent_name)
                    .join(AgentExecution, AgentExecution.id == AgentReasoningStep.execution_id)
                    .where(AgentExecution.investigation_id == uuid.UUID(case_id))
                    .order_by(AgentReasoningStep.timestamp.asc())
                )
                steps = result.all()
                for step, agent_name in steps:
                    await websocket.send_text(json.dumps({
                        "event_id": str(step.id),
                        "event_type": "investigation_event",
                        "investigation_id": case_id,
                        "execution_id": str(step.execution_id),
                        "agent_name": agent_name,
                        "step_type": step.step_type,
                        "payload": step.content,
                        "timestamp": step.timestamp.isoformat() if step.timestamp else None,
                        "confidence": None,
                        "evidence_ids": step.evidence_ids or [],
                        "tool_call_id": None
                    }))
            except Exception as e:
                print(f"Error replaying steps: {e}")

    try:
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        manager.disconnect(websocket, case_id=case_id)
