"""
Tool call durations must be measured from the real operation, never defaulted.
"""
import asyncio
import uuid

import pytest
from sqlalchemy import select

from agents.base import BaseAgent
from database.session import AsyncSessionLocal
from models.investigation import (
    AgentExecution,
    AgentToolCall,
    InvestigationCase,
    InvestigationStatus,
    Severity,
)


class _ProbeAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="Probe Agent", role="test", goal="exercise run_tool")

    async def analyze(self, db, case, **kwargs):
        raise NotImplementedError


async def _new_execution(session):
    case = InvestigationCase(id=uuid.uuid4(), title="tool timing", status=InvestigationStatus.OPEN, severity=Severity.LOW)
    session.add(case)
    await session.commit()
    agent = _ProbeAgent()
    execution = await agent.start_execution(session, case.id)
    await session.commit()
    return agent, case, execution


@pytest.mark.asyncio
async def test_tool_duration_reflects_actual_execution_time():
    async with AsyncSessionLocal() as session:
        agent, case, execution = await _new_execution(session)

        async def slow_op():
            await asyncio.sleep(0.15)
            return ["a", "b"]

        async def fast_op():
            return []

        await agent.run_tool(session, execution, "slow_tool", {"k": 1}, slow_op, lambda r: {"count": len(r)})
        await agent.run_tool(session, execution, "fast_tool", {"k": 2}, fast_op, lambda r: {"count": len(r)})

        calls = {
            c.tool_name: c for c in (await session.execute(
                select(AgentToolCall).where(AgentToolCall.execution_id == execution.id)
            )).scalars().all()
        }

    slow, fast = calls["slow_tool"], calls["fast_tool"]
    assert 150.0 <= slow.duration_ms < 2000.0
    assert fast.duration_ms < 50.0
    assert slow.duration_ms != 850.0 and fast.duration_ms != 850.0
    assert slow.status == "Completed"
    assert slow.output == {"count": 2}
    assert slow.input == {"k": 1}
    assert slow.started_at is not None and slow.completed_at is not None
    wall_ms = (slow.completed_at - slow.started_at).total_seconds() * 1000.0
    assert abs(wall_ms - slow.duration_ms) < 50.0
    assert slow.error_message is None

    async with AsyncSessionLocal() as session:
        stored_exec = await session.get(AgentExecution, execution.id)
        assert stored_exec.tool_call_count == 2
        assert stored_exec.tool_execution_time_ms == pytest.approx(slow.duration_ms + fast.duration_ms)


@pytest.mark.asyncio
async def test_failed_tool_is_recorded_as_failed_and_reraised():
    async with AsyncSessionLocal() as session:
        agent, case, execution = await _new_execution(session)

        async def failing_op():
            await asyncio.sleep(0.05)
            raise ConnectionError("vector store unreachable")

        with pytest.raises(ConnectionError):
            await agent.run_tool(session, execution, "memory_search", {}, failing_op, lambda r: {})

        call = (await session.execute(
            select(AgentToolCall).where(AgentToolCall.execution_id == execution.id)
        )).scalar_one()

    assert call.status == "Failed"
    assert call.output is None
    assert "ConnectionError: vector store unreachable" in call.error_message
    assert call.duration_ms >= 50.0


@pytest.mark.asyncio
async def test_llm_execution_time_is_measured():
    async with AsyncSessionLocal() as session:
        agent, case, execution = await _new_execution(session)

        async def fake_generation():
            await asyncio.sleep(0.1)
            return "{}"

        await agent.call_llm_with_timeout(fake_generation(), timeout_seconds=5, execution=execution)
        assert 100.0 <= execution.llm_execution_time_ms < 2000.0
