"""
Investigation memory: indicator extraction, knowledge provenance, durable write
ordering, failure/retry behaviour, versioning, orphan reconciliation and retrieval.

All tests run against the real PostgreSQL test database and the real Qdrant test
collection; no vector store or embedding mocks.
"""
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from api.main import app
from core.auth import get_current_user
from core.config import settings
from database.session import AsyncSessionLocal
from memory.case_inputs import build_fingerprint, load_case_memory_inputs, semantic_text
from memory.indicators import extract_case_indicators
from memory.knowledge_builder import knowledge_builder
from memory.maintenance import memory_status, reconcile_memory
from memory.service import memory_service
from memory.vector_repository import MemoryBackendAPIError
from models.event import Event
from models.investigation import (
    EvidenceItem,
    InvestigationCase,
    InvestigationMemory,
    InvestigationReport,
    InvestigationStatus,
    Severity,
)
from models.mitre import AttackTechnique
from models.user import User, UserRole

BASE_TIME = datetime(2026, 9, 18, 9, 0, tzinfo=timezone.utc)


@pytest_asyncio.fixture(autouse=True)
async def clean_memory_collection():
    """Each test starts with an empty memory collection and no memory records."""
    async with AsyncSessionLocal() as session:
        for row in (await session.execute(select(InvestigationMemory))).scalars().all():
            await session.delete(row)
        await session.commit()
    try:
        await memory_service.vector_repo.qdrant.delete_collection(memory_service.vector_repo.collection_name)
    except Exception:
        pass
    await memory_service.initialize()
    yield


async def make_case(
    session,
    *,
    title,
    host="finance-pc-04",
    user="asmith",
    ip="198.51.100.25",
    command="powershell.exe -enc SQBFAFgA",
    technique=("T1059.001", "PowerShell", "Execution"),
    summary="Encoded PowerShell executed on the host by the user.",
    status=InvestigationStatus.RESOLVED,
    with_report=True,
    offset_minutes=0,
):
    case_id, event_id = uuid.uuid4(), uuid.uuid4()
    timestamp = BASE_TIME + timedelta(minutes=offset_minutes)
    session.add(InvestigationCase(
        id=case_id, title=title, description=f"Detection rule matched on {host}",
        status=status, severity=Severity.HIGH, confidence_score=0.8,
    ))
    session.add(Event(
        id=event_id, timestamp=timestamp, hostname=host, user_name=user, source="Sysmon",
        event_type="PROCESS_EXECUTION", severity="HIGH",
        raw_log={"metadata": {"process_name": "powershell.exe", "command_line": command, "ip_address": ip}},
        metadata_={"process_name": "powershell.exe", "command_line": command, "ip_address": ip},
        payload_sha256="0" * 64,
    ))
    evidence_id = uuid.uuid4()
    session.add(EvidenceItem(
        id=evidence_id, case_id=case_id, event_id=event_id, evidence_type="PROCESS_EXECUTION",
        source="Sysmon", timestamp=timestamp, artifact=command, reason="Suspicious command line execution",
        importance_score=0.9,
    ))
    session.add(AttackTechnique(
        case_id=case_id, technique_id=technique[0], technique_name=technique[1],
        tactic=technique[2], confidence=0.9, reason="rule",
    ))
    if with_report:
        session.add(InvestigationReport(
            case_id=case_id, version=1, is_current=True, status="complete",
            generated_at=timestamp, title=title, severity="HIGH", confidence_score=0.8,
            executive_summary=summary,
            finding_ids=[], recommendations=[{"action": f"Isolate {host}", "rationale": "r", "evidence_ids": [str(evidence_id)]}],
            mitre_techniques=[{"technique_id": technique[0], "technique_name": technique[1], "tactic": technique[2], "reason": "r", "source": "detection_rule", "evidence_ids": []}],
            timeline=[{"time": timestamp.isoformat(), "action": "Encoded PowerShell execution", "details": command, "evidence_ids": [str(evidence_id)]}],
            timeline_source="timeline_agent", evidence_ids=[str(evidence_id)],
            agent_runs=[{"agent": "SOC Lead", "execution_id": None, "status": "completed", "error": None}],
        ))
    await session.commit()
    return case_id


# ---------------------------------------------------------------- indicators

@pytest.mark.asyncio
async def test_indicators_come_from_events_not_evidence_type_labels():
    async with AsyncSessionLocal() as session:
        case_id = await make_case(session, title="Indicator extraction")
        inputs = await load_case_memory_inputs(session, case_id)

    indicators = inputs.indicators
    # Evidence type is "PROCESS_EXECUTION"; the indicators live in the linked event
    assert indicators.ips == {"198.51.100.25"}
    assert indicators.users == {"asmith"}
    assert indicators.hosts == {"finance-pc-04"}
    assert indicators.processes == {"powershell.exe"}
    assert "powershell.exe -enc SQBFAFgA" in indicators.commands
    assert indicators.iocs() and indicators.assets()
    assert build_fingerprint(inputs).ioc_hash is not None


@pytest.mark.asyncio
async def test_ioc_hash_differs_per_case_and_is_none_without_indicators():
    async with AsyncSessionLocal() as session:
        a = await make_case(session, title="A", ip="198.51.100.25", command="powershell.exe -enc AAA")
        b = await make_case(session, title="B", ip="203.0.113.9", command="powershell.exe -enc BBB")
        fp_a = build_fingerprint(await load_case_memory_inputs(session, a))
        fp_b = build_fingerprint(await load_case_memory_inputs(session, b))

        empty_case = uuid.uuid4()
        session.add(InvestigationCase(id=empty_case, title="No evidence", status=InvestigationStatus.RESOLVED, severity=Severity.LOW))
        await session.commit()
        fp_empty = build_fingerprint(await load_case_memory_inputs(session, empty_case))

    assert fp_a.ioc_hash != fp_b.ioc_hash
    assert fp_empty.ioc_hash is None  # an empty IOC set must never match another empty set


# ---------------------------------------------------------------- knowledge provenance

@pytest.mark.asyncio
async def test_knowledge_is_built_from_report_without_calling_an_llm():
    async with AsyncSessionLocal() as session:
        case_id = await make_case(session, title="Report-sourced knowledge")
        with patch("services.llm_service.llm_service.generate", new_callable=AsyncMock, side_effect=AssertionError("LLM must not be called")):
            knowledge, fingerprint = await knowledge_builder.build(session, case_id)

    assert knowledge.metadata.knowledge_source == "investigation_report"
    assert knowledge.metadata.source_report_version == 1
    assert knowledge.metadata.llm_model is None
    assert knowledge.investigation.executive_summary == "Encoded PowerShell executed on the host by the user."
    assert knowledge.recommendations.immediate_actions == ["Isolate finance-pc-04"]
    assert knowledge.attack.mitre_techniques == ["T1059.001"]
    assert knowledge.attack.attack_type is None and knowledge.attack.campaign is None  # never invented
    assert knowledge.evidence.ips == ["198.51.100.25"]
    assert fingerprint.timeline_hash


@pytest.mark.asyncio
async def test_knowledge_from_case_without_report_is_labelled():
    async with AsyncSessionLocal() as session:
        case_id = await make_case(session, title="Legacy resolved case", with_report=False)
        knowledge, _ = await knowledge_builder.build(session, case_id)

    assert knowledge.metadata.knowledge_source == "case_evidence"
    assert knowledge.metadata.source_report_id is None
    assert knowledge.investigation.executive_summary is None
    assert "resolved without an investigation report" in knowledge.investigation.summary
    assert knowledge.recommendations.immediate_actions == []


# ---------------------------------------------------------------- indexing and retrieval

@pytest.mark.asyncio
async def test_index_persists_record_then_vector_and_is_retrievable():
    async with AsyncSessionLocal() as session:
        indexed_case = await make_case(session, title="Encoded PowerShell on finance workstation")
        record = await memory_service.index_case(session, indexed_case)

        assert record.vector_indexed_at is not None
        assert record.knowledge_version == 1
        assert record.knowledge_source == "investigation_report"
        assert record.qdrant_id == str(record.id)
        assert await memory_service.vector_repo.list_point_ids() == [str(record.id)]

        # A new, similar case retrieves it
        similar_case = await make_case(
            session, title="Encoded PowerShell execution on finance workstation",
            status=InvestigationStatus.OPEN, with_report=False, offset_minutes=30,
        )
        inputs = await load_case_memory_inputs(session, similar_case)
        results = await memory_service.find_similar_cases(
            session, build_fingerprint(inputs), inputs.indicators, semantic_text(inputs),
            exclude_investigation_id=str(similar_case),
        )

    assert [r.investigation_id for r in results] == [str(indexed_case)]
    hit = results[0]
    assert hit.semantic_score > 0.5
    assert hit.mitre_overlap_score == 1.0
    assert hit.ioc_overlap_score == 1.0
    assert hit.asset_overlap_score == 1.0
    assert hit.shared_mitre_techniques == ["T1059.001"]
    assert "198.51.100.25" in hit.shared_iocs
    assert set(hit.shared_assets) == {"user:asmith", "host:finance-pc-04"}
    assert hit.knowledge_object.investigation.title == "Encoded PowerShell on finance workstation"
    assert hit.similarity_score > 0.75


@pytest.mark.asyncio
async def test_unrelated_case_is_filtered_out_by_the_similarity_threshold():
    """
    The embedding model gives any two security texts a high baseline similarity, so a
    semantic-only hit must not be reported as a historical match.
    """
    async with AsyncSessionLocal() as session:
        related = await make_case(session, title="Encoded PowerShell on finance workstation")
        unrelated = await make_case(
            session, title="Database backup job completed", host="db-server-02", user="svc_backup",
            ip="10.1.1.5", command="sqlcmd -Q backup", technique=("T1078", "Valid Accounts", "Persistence"),
            summary="Routine backup service activity reviewed and closed.", offset_minutes=120,
        )
        await memory_service.index_case(session, related)
        await memory_service.index_case(session, unrelated)

        query_case = await make_case(
            session, title="Encoded PowerShell execution on finance workstation",
            status=InvestigationStatus.OPEN, with_report=False, offset_minutes=200,
        )
        inputs = await load_case_memory_inputs(session, query_case)
        args = (session, build_fingerprint(inputs), inputs.indicators, semantic_text(inputs))

        default_results = await memory_service.find_similar_cases(*args, exclude_investigation_id=str(query_case))
        with patch.object(settings, "MEMORY_MIN_SIMILARITY", 0.0):
            all_results = await memory_service.find_similar_cases(*args, exclude_investigation_id=str(query_case))

    assert [r.investigation_id for r in default_results] == [str(related)]
    scores = {r.investigation_id: r.similarity_score for r in all_results}
    assert scores[str(related)] > scores[str(unrelated)]
    assert scores[str(unrelated)] < settings.MEMORY_MIN_SIMILARITY
    # The unrelated case is only reachable through semantic similarity, with no real overlap
    unrelated_hit = next(r for r in all_results if r.investigation_id == str(unrelated))
    assert unrelated_hit.semantic_score > 0.4
    assert unrelated_hit.mitre_overlap_score == 0.0
    assert unrelated_hit.ioc_overlap_score == 0.0
    assert unrelated_hit.asset_overlap_score == 0.0


@pytest.mark.asyncio
async def test_case_never_matches_itself():
    async with AsyncSessionLocal() as session:
        case_id = await make_case(session, title="Self match check")
        await memory_service.index_case(session, case_id)
        inputs = await load_case_memory_inputs(session, case_id)
        results = await memory_service.find_similar_cases(
            session, build_fingerprint(inputs), inputs.indicators, semantic_text(inputs),
            exclude_investigation_id=str(case_id),
        )
    assert results == []


# ---------------------------------------------------------------- failure handling

@pytest.mark.asyncio
async def test_vector_failure_leaves_pending_record_and_retry_completes_it():
    async with AsyncSessionLocal() as session:
        case_id = await make_case(session, title="Vector failure handling")

        with patch.object(memory_service.vector_repo, "upsert", side_effect=MemoryBackendAPIError("qdrant down")):
            with pytest.raises(MemoryBackendAPIError):
                await memory_service.index_case(session, case_id)

        pending = (await session.execute(
            select(InvestigationMemory).where(InvestigationMemory.investigation_id == case_id)
        )).scalars().all()
        assert len(pending) == 1
        assert pending[0].vector_indexed_at is None  # durable record exists
        assert await memory_service.vector_repo.list_point_ids() == []  # but no vector

        # Retry resumes the pending record instead of creating a second version
        resumed = await memory_service.index_case(session, case_id)
        await session.refresh(resumed)
        records = (await session.execute(
            select(InvestigationMemory).where(InvestigationMemory.investigation_id == case_id)
        )).scalars().all()

    assert resumed.id == pending[0].id
    assert len(records) == 1
    assert resumed.vector_indexed_at is not None
    assert await memory_service.vector_repo.list_point_ids() == [str(resumed.id)]


@pytest.mark.asyncio
async def test_reindexing_supersedes_previous_version_and_vector():
    async with AsyncSessionLocal() as session:
        case_id = await make_case(session, title="Versioned memory")
        first = await memory_service.index_case(session, case_id)

        report = (await session.execute(
            select(InvestigationReport).where(InvestigationReport.case_id == case_id)
        )).scalar_one()
        report.executive_summary = "Revised summary after analyst review."
        await session.commit()

        second = await memory_service.index_case(session, case_id)
        records = {r.knowledge_version: r for r in (await session.execute(
            select(InvestigationMemory).where(InvestigationMemory.investigation_id == case_id)
        )).scalars().all()}

    assert set(records) == {1, 2}
    assert records[1].is_latest is False and records[2].is_latest is True
    assert second.knowledge_object["investigation"]["executive_summary"] == "Revised summary after analyst review."
    assert await memory_service.vector_repo.list_point_ids() == [str(second.id)]
    assert str(first.id) not in await memory_service.vector_repo.list_point_ids()


@pytest.mark.asyncio
async def test_reconcile_removes_orphan_vectors_and_repairs_pending_records():
    async with AsyncSessionLocal() as session:
        indexed_case = await make_case(session, title="Healthy record")
        healthy = await memory_service.index_case(session, indexed_case)

        # Orphan: a vector with no memory record (as produced by pre-fix indexing failures)
        orphan_id = str(uuid.uuid4())
        await memory_service.vector_repo.upsert(
            id=orphan_id, vector=memory_service.embed("orphaned test vector"),
            payload={"investigation_id": str(uuid.uuid4())},
        )
        # Pending: a record whose vector write never happened
        pending_case = await make_case(session, title="Pending record", offset_minutes=60)
        with patch.object(memory_service.vector_repo, "upsert", side_effect=MemoryBackendAPIError("down")):
            with pytest.raises(MemoryBackendAPIError):
                await memory_service.index_case(session, pending_case)

        before = await memory_status(session, memory_service)
        result = await reconcile_memory(session, memory_service)
        after = await memory_status(session, memory_service)
        point_ids = set(await memory_service.vector_repo.list_point_ids())

    assert before["orphan_points"] == 1
    assert before["pending_records"] == [str(pending_case)]
    assert result["deleted_orphan_points"] == 1
    assert result["repaired_records"] == [str(pending_case)]
    assert orphan_id not in point_ids
    assert str(healthy.id) in point_ids
    assert after["orphan_points"] == 0 and after["pending_records"] == [] and after["missing_points"] == 0


# ---------------------------------------------------------------- task and API

@pytest.mark.asyncio
async def test_celery_task_indexes_resolved_case_and_refuses_unresolved():
    from tests.support.celery import running_test_worker
    from workers.tasks.memory_tasks import index_resolved_investigation_task
    import asyncio

    async with AsyncSessionLocal() as session:
        resolved_case = await make_case(session, title="Task indexed case")
        open_case = await make_case(session, title="Unreviewed case", status=InvestigationStatus.OPEN, offset_minutes=15)

    with running_test_worker():
        resolved_result = await asyncio.to_thread(
            index_resolved_investigation_task.delay(str(resolved_case)).get, timeout=120
        )
        open_result = await asyncio.to_thread(
            index_resolved_investigation_task.delay(str(open_case)).get, timeout=120
        )

    assert resolved_result["indexed"] is True
    assert resolved_result["knowledge_source"] == "investigation_report"
    assert open_result == {"indexed": False, "reason": "case status is OPEN"}

    async with AsyncSessionLocal() as session:
        records = (await session.execute(select(InvestigationMemory))).scalars().all()
    assert [str(r.investigation_id) for r in records] == [str(resolved_case)]


@pytest.mark.asyncio
async def test_celery_task_fails_loudly_when_indexing_cannot_succeed():
    from tests.support.celery import running_test_worker
    from workers.tasks.memory_tasks import index_resolved_investigation_task
    import asyncio

    missing_case = str(uuid.uuid4())
    with running_test_worker():
        async_result = index_resolved_investigation_task.apply_async(args=[missing_case], retry=False, max_retries=0)
        with pytest.raises(Exception):
            await asyncio.to_thread(async_result.get, timeout=120)
        assert async_result.state == "FAILURE"


@pytest.mark.asyncio
async def test_memory_status_endpoint_reports_real_state():
    admin = User(id=uuid.uuid4(), email="memory-admin@test.local", hashed_password="x", role=UserRole.ADMIN, is_active=True)
    app.dependency_overrides[get_current_user] = lambda: admin
    try:
        async with AsyncSessionLocal() as session:
            case_id = await make_case(session, title="Status endpoint case")
            await make_case(session, title="Not indexed case", offset_minutes=90)
            await memory_service.index_case(session, case_id)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            status = (await ac.get("/memory/status")).json()
    finally:
        app.dependency_overrides.clear()

    assert status["resolved_cases"] >= 2
    assert status["resolved_cases_indexed"] == 1
    assert str(case_id) not in status["resolved_cases_not_indexed"]
    assert status["vector_indexed_records"] == 1
    assert status["orphan_points"] == 0
    assert status["collection"].startswith("test_")
