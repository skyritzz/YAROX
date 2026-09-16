from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Callable, Awaitable
import time
from sqlalchemy.ext.asyncio import AsyncSession
from models.investigation import InvestigationCase, AgentExecution, AgentReasoningStep, AgentToolCall
from websocket.investigation_ws import manager as ws_manager
from core.utils import sanitize_evidence
import json
import uuid
import asyncio
from datetime import datetime, timezone

class BaseAgent(ABC):
    def __init__(self, name: str, role: str, goal: str, available_tools: list[str] = None):
        self.name = name
        self.role = role
        self.goal = goal
        self.available_tools = available_tools or []

    async def start_execution(self, db: AsyncSession, case_id: uuid.UUID) -> AgentExecution:
        execution = AgentExecution(
            id=uuid.uuid4(),
            investigation_id=case_id,
            agent_name=self.name,
            status="running",
            reasoning_step_count=0,
            tool_call_count=0
        )
        db.add(execution)
        await db.flush()
        return execution
        
    async def finish_execution(self, db: AsyncSession, execution: AgentExecution, status: str = "completed", confidence: float = None):
        execution.status = status
        execution.completed_at = datetime.now(timezone.utc)
        
        # Ensure started_at exists before calculating delta
        if execution.started_at:
            # Ensure timezone awareness matches for subtraction
            started = execution.started_at
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            delta = execution.completed_at - started
            execution.total_execution_time_ms = delta.total_seconds() * 1000.0

        if confidence is not None:
            execution.confidence = confidence
        await db.commit()

    async def emit_step(self, db: AsyncSession, execution: AgentExecution, step_type: str, content: dict, confidence: Optional[float] = None, evidence_ids: list[str] = None, tool_call_id: Optional[str] = None):
        """
        Emits a reasoning step to both the DB and the WebSocket using the Unified Investigation Event Schema.
        step_type: observation, tool_call, reasoning, decision, handoff, failed
        """
        if evidence_ids is None:
            evidence_ids = []
            
        # Save to DB
        step = AgentReasoningStep(
            execution_id=execution.id,
            step_type=step_type,
            content=content
        )
        db.add(step)
        
        # Increment cached metrics on the execution
        if step_type in ("reasoning_started", "reasoning_complete"):
            execution.reasoning_step_count += 1
        elif step_type == "tool_call_started":
            execution.tool_call_count += 1

        await db.commit()

        # Broadcast unified event over WS
        await ws_manager.broadcast({
            "event_id": str(step.id),
            "investigation_id": str(execution.investigation_id),
            "execution_id": str(execution.id),
            "timestamp": step.timestamp.isoformat() if step.timestamp else datetime.now(timezone.utc).isoformat(),
            "agent_name": self.name,
            "event_type": "investigation_event",
            "step_type": step_type,
            "payload": content,
            "confidence": confidence,
            "evidence_ids": evidence_ids,
            "tool_call_id": tool_call_id
        })

    async def run_tool(
        self,
        db: AsyncSession,
        execution: AgentExecution,
        tool_name: str,
        tool_input: Dict[str, Any],
        operation: Callable[[], Awaitable[Any]],
        summarize_output: Callable[[Any], Dict[str, Any]],
    ) -> Any:
        """
        Executes a real tool operation and records a measured AgentToolCall.

        ``tool_input`` and the ``summarize_output`` result are stored as metadata; callers must
        pass descriptive fields (counts, identifiers), never raw secrets or full evidence payloads.
        Failures are recorded with status "Failed" and the exception is re-raised.
        """
        await self.emit_step(db, execution, "tool_call_started", {
            "text": f"Running tool {tool_name}.",
            "tool": tool_name,
            "input": tool_input,
        })

        started_at = datetime.now(timezone.utc)
        start = time.perf_counter()
        result = None
        error: Optional[BaseException] = None
        try:
            result = await operation()
        except Exception as e:
            error = e
        duration_ms = (time.perf_counter() - start) * 1000.0
        completed_at = datetime.now(timezone.utc)

        tool_call = AgentToolCall(
            id=uuid.uuid4(),
            execution_id=execution.id,
            tool_name=tool_name,
            input=tool_input,
            output=summarize_output(result) if error is None else None,
            duration_ms=duration_ms,
            status="Completed" if error is None else "Failed",
            started_at=started_at,
            completed_at=completed_at,
            error_message=None if error is None else f"{type(error).__name__}: {error}",
        )
        db.add(tool_call)
        execution.tool_execution_time_ms = (execution.tool_execution_time_ms or 0.0) + duration_ms
        await db.commit()

        await self.emit_step(db, execution, "tool_call_complete", {
            "text": f"Tool {tool_name} {'completed' if error is None else 'failed'} in {duration_ms:.1f} ms.",
            "tool": tool_name,
            "status": tool_call.status,
            "duration_ms": duration_ms,
            "output": tool_call.output,
            "error": tool_call.error_message,
        }, tool_call_id=str(tool_call.id))

        if error is not None:
            raise error
        return result

    async def call_llm_with_timeout(self, coroutine, timeout_seconds: int = 120, execution: Optional[AgentExecution] = None):
        """
        Wraps an LLM generation call with a strict timeout.
        If it times out or errors, raises an exception to be caught for degraded fallback.
        When an execution is given, the measured wall-clock LLM time is added to it.
        """
        start = time.perf_counter()
        try:
            return await asyncio.wait_for(coroutine, timeout=timeout_seconds)
        except asyncio.TimeoutError:
            raise Exception("LLM request timed out.")
        except Exception as e:
            raise Exception(f"LLM request failed: {str(e)}")
        finally:
            if execution is not None:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                execution.llm_execution_time_ms = (execution.llm_execution_time_ms or 0.0) + elapsed_ms

    @abstractmethod
    async def analyze(self, db: AsyncSession, case: InvestigationCase, **kwargs) -> Dict[str, Any]:
        """Main entry point for agent logic. Must implement the execution loop and fallback."""
        pass
