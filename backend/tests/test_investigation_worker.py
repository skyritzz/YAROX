"""
Investigations execute on Celery workers, not in the API process.

The worker runs in-process here (bound to the isolated test broker) but is a real
Celery worker consuming a real Redis queue, with its own event loop and its own
database engine, exactly like the deployed worker.
"""
import asyncio
import uuid
from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from api.main import app
from core.auth import get_current_user
from database.session import AsyncSessionLocal
from models.investigation import (
    AgentExecution,
    InvestigationCase,
    InvestigationReport,
    InvestigationStatus,
)
from models.user import User, UserRole
from services.investigation_runner import InvestigationDispatchError, dispatch_investigation
from tests.support.celery import running_test_worker
from tests.support.llm_double import EvidenceCitingLLM
from tests.test_report_persistence import _create_detected_case
from workers.tasks.investigation_tasks import run_investigation_task


@pytest_asyncio.fixture
async def analyst_client():
    analyst = User(id=uuid.uuid4(), email=f"worker-{uuid.uuid4().hex[:8]}@test.local", hashed_password="x", role=UserRole.ANALYST, is_active=True)
    async with AsyncSessionLocal() as session:
        session.add(analyst)
        await session.commit()
    app.dependency_overrides[get_current_user] = lambda: analyst
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_worker_runs_the_full_investigation_and_persists_a_report():
    case_id, event_id = await _create_detected_case()
    llm = EvidenceCitingLLM()

    with patch("services.llm_service.llm_service.generate", side_effect=llm.generate):
        with running_test_worker():
            outcome = await asyncio.to_thread(run_investigation_task.delay(str(case_id)).get, timeout=180)

    assert outcome["status"] == "completed"
    assert outcome["report_status"] == "complete"

    async with AsyncSessionLocal() as session:
        case = await session.get(InvestigationCase, case_id)
        executions = (await session.execute(
            select(AgentExecution).where(AgentExecution.investigation_id == case_id)
        )).scalars().all()
        report = (await session.execute(
            select(InvestigationReport).where(InvestigationReport.case_id == case_id, InvestigationReport.is_current.is_(True))
        )).scalar_one()

    # The work really happened in the worker process, against the real database
    assert case.status == InvestigationStatus.WAITING_FOR_REVIEW
    assert {e.agent_name for e in executions} == {
        "Memory Agent", "Triage Analyst", "Forensic Timeline Analyst", "Threat Intel Analyst", "SOC Lead",
    }
    assert all(e.status == "completed" for e in executions)
    assert report.version == 1 and report.executive_summary
    assert str(report.id) == outcome["report_id"]


@pytest.mark.asyncio
async def test_worker_runs_consecutive_investigations_in_separate_event_loops():
    """
    Each task runs in its own ``asyncio.run`` loop. Agents must use the task's own
    NullPool engine: with the module-level engine, the second task fails with
    "attached to a different loop" once its pooled connections belong to the first loop.
    """
    first_case, _ = await _create_detected_case()
    second_case, _ = await _create_detected_case()
    llm = EvidenceCitingLLM()

    with patch("services.llm_service.llm_service.generate", side_effect=llm.generate):
        with running_test_worker():
            first = await asyncio.to_thread(run_investigation_task.delay(str(first_case)).get, timeout=180)
            second = await asyncio.to_thread(run_investigation_task.delay(str(second_case)).get, timeout=180)

    assert first["status"] == "completed"
    assert second["status"] == "completed", f"second task in the same worker failed: {second}"

    async with AsyncSessionLocal() as session:
        for case_id in (first_case, second_case):
            report = (await session.execute(
                select(InvestigationReport).where(InvestigationReport.case_id == case_id, InvestigationReport.is_current.is_(True))
            )).scalar_one()
            assert report.status == "complete"


@pytest.mark.asyncio
async def test_analyze_endpoint_queues_a_worker_task_instead_of_running_in_process(analyst_client):
    case_id, _ = await _create_detected_case()

    with patch("services.investigation_runner.run_investigation_task.delay") as mock_delay:
        mock_delay.return_value.id = "task-123"
        res = await analyst_client.post(f"/investigations/{case_id}/analyze")

    assert res.status_code == 200
    body = res.json()
    assert body["task_id"] == "task-123"
    assert "worker" in body["message"].lower()
    mock_delay.assert_called_once_with(str(case_id))

    # Nothing ran in the API process
    async with AsyncSessionLocal() as session:
        executions = (await session.execute(
            select(AgentExecution).where(AgentExecution.investigation_id == case_id)
        )).scalars().all()
        case = await session.get(InvestigationCase, case_id)
    assert executions == []
    assert case.status == InvestigationStatus.OPEN


@pytest.mark.asyncio
async def test_analyze_returns_503_when_the_broker_is_unreachable(analyst_client):
    case_id, _ = await _create_detected_case()

    with patch("services.investigation_runner.run_investigation_task.delay", side_effect=OSError("broker down")):
        res = await analyst_client.post(f"/investigations/{case_id}/analyze")

    assert res.status_code == 503
    assert "Celery worker" in res.json()["detail"]


def test_dispatch_error_is_typed():
    with patch("services.investigation_runner.run_investigation_task.delay", side_effect=OSError("broker down")):
        with pytest.raises(InvestigationDispatchError):
            dispatch_investigation(str(uuid.uuid4()))


@pytest.mark.asyncio
async def test_detection_consumer_dispatches_to_a_worker():
    from consumers.detection_consumer import handle_event_stored
    from consumers.db_writer import handle_event_normalized
    from plugins.parsers.generic import generic_parser
    from unittest.mock import AsyncMock

    raw = {
        "timestamp": "2026-09-18T11:00:00Z",
        "hostname": f"WS-{uuid.uuid4().hex[:6]}",
        "user": "detection-dispatch",
        "source": "Sysmon",
        "event_type": "Process Creation",
        "severity": "MEDIUM",
        "metadata": {"process_name": "powershell.exe", "command_line": "powershell.exe -enc AAA"},
    }
    data = generic_parser.parse(raw)
    event_id = uuid.uuid4()
    data["id"] = str(event_id)
    with patch("consumers.db_writer.event_bus.publish", new_callable=AsyncMock):
        await handle_event_normalized(data)

    with patch("services.investigation_runner.run_investigation_task.delay") as mock_delay:
        mock_delay.return_value.id = "task-abc"
        await handle_event_stored({"id": str(event_id)})

    mock_delay.assert_called_once()

    async with AsyncSessionLocal() as session:
        case_id = uuid.UUID(mock_delay.call_args[0][0])
        executions = (await session.execute(
            select(AgentExecution).where(AgentExecution.investigation_id == case_id)
        )).scalars().all()
    assert executions == []  # detection does not run agents in the API process


def test_worker_task_imports_do_not_depend_on_working_directory():
    """
    The backend packages are namespace packages resolved through sys.path. A worker
    process does not necessarily run from the backend directory, which made lazy imports
    inside tasks fail with ModuleNotFoundError at runtime (reproduced on the live worker).
    """
    import subprocess
    import sys as _sys
    from workers.celery_app import BACKEND_DIR

    result = subprocess.run(
        [_sys.executable, "-c", "from workers.celery_app import celery_app; from agents.orchestrator import orchestrator; print('ok')"],
        cwd="/", capture_output=True, text=True, env={"PYTHONPATH": "", "PATH": "/usr/local/bin:/usr/bin:/bin"},
    )
    assert result.returncode != 0, "this check needs a cwd where the packages are not importable"

    result = subprocess.run(
        [_sys.executable, "-c",
         f"import sys; sys.path.insert(0, {BACKEND_DIR!r});"
         "from workers.celery_app import celery_app;"
         "from agents.orchestrator import orchestrator;"
         "from workers.tasks.investigation_tasks import run_investigation_task; print('ok')"],
        cwd="/", capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


def test_orchestrator_is_imported_at_worker_module_scope():
    """
    The worker parent imports this task module at startup and forked task processes
    inherit it. Importing the orchestrator lazily inside the task body failed with
    ModuleNotFoundError in the forked child on the live worker, so the import must stay
    at module scope.
    """
    import inspect

    import workers.tasks.investigation_tasks as task_module

    assert hasattr(task_module, "orchestrator"), "orchestrator must be imported at module scope"
    source = inspect.getsource(task_module.run_investigation_task)
    assert "import" not in source.split("async def _run()")[1].split("async with")[0], \
        "the task body must not import application modules lazily"
