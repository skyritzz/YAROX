import pytest
import uuid
import json
from datetime import datetime, timezone
from pydantic import ValidationError
from sqlalchemy.future import select

from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from core.config import settings
from models.investigation import (
    InvestigationCase,
    InvestigationStatus,
    Severity,
    EvidenceItem,
    AgentExecution,
    AgentReasoningStep,
    InvestigationMemory
)
from models.mitre import AttackTechnique
from schemas.memory import (
    InvestigationKnowledgeObject,
    InvestigationFingerprint,
    TimelineEvent,
    TimelineSection
)
from memory.knowledge_builder import knowledge_builder, _compute_timeline_hash
from memory.service import memory_service, InvestigationMemoryService
from memory.vector_repository import QdrantRepository
from unittest.mock import patch, AsyncMock

test_engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool, echo=False)
AsyncSessionLocal = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


# -----------------------------------------------------------------------------
# Part 3: KnowledgeBuilder Direct & Schema Tests
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_knowledge_builder_async_loading_no_missing_greenlet():
    """
    Test A: A real AsyncSession + InvestigationCase + required relationships
    (mitre_techniques, evidence_items, agent_executions) can be loaded and processed
    by KnowledgeBuilder without triggering SQLAlchemy MissingGreenlet exception.
    """
    case_id = uuid.uuid4()
    exec_id = uuid.uuid4()
    
    async with AsyncSessionLocal() as session:
        case = InvestigationCase(
            id=case_id,
            title="E2E Brute Force Async Test",
            description="Test incident for async loading",
            status=InvestigationStatus.RESOLVED,
            severity=Severity.HIGH,
            confidence_score=0.85
        )
        session.add(case)
        
        technique = AttackTechnique(
            case_id=case_id,
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            confidence=1.0
        )
        session.add(technique)
        
        evidence = EvidenceItem(
            case_id=case_id,
            evidence_type="ip",
            source="suricata",
            timestamp=datetime.now(timezone.utc),
            artifact="198.51.100.25",
            reason="Multiple failed authentication attempts",
            importance_score=0.8
        )
        session.add(evidence)
        
        execution = AgentExecution(
            id=exec_id,
            investigation_id=case_id,
            agent_name="Forensic Timeline Analyst",
            status="completed",
            confidence=0.9
        )
        session.add(execution)
        
        step = AgentReasoningStep(
            execution_id=exec_id,
            step_type="decision_made",
            content={"text": "Verified high frequency logon failure patterns."}
        )
        session.add(step)
        await session.commit()

    # Build knowledge object through KnowledgeBuilder on fresh session
    async with AsyncSessionLocal() as session:
        mock_llm_response = json.dumps({
            "summary": "Brute force credential attack against administrator account",
            "executive_summary": "Attacker performed automated brute force.",
            "attack_type": "Brute Force",
            "malware_family": None,
            "campaign": "Unknown",
            "kill_chain": ["Credential Access"],
            "important_events": [
                {"time": "2026-08-23T01:00:00Z", "action": "Failed Login", "details": "IP 198.51.100.25 tried 50 passwords"}
            ],
            "attack_story": "The adversary attempted brute force authentication.",
            "immediate_actions": ["Block IP 198.51.100.25"],
            "long_term_actions": ["Enforce MFA"],
            "lessons_learned": "Implement rate limiting on edge services."
        })
        
        with patch("services.llm_service.llm_service.generate", new_callable=AsyncMock, return_value=mock_llm_response):
            ko, fp = await knowledge_builder.build(session, case_id)
            
            assert ko.investigation.title == "E2E Brute Force Async Test"
            assert ko.investigation.severity == "HIGH"
            assert ko.attack.mitre_techniques == ["T1110"]
            assert "198.51.100.25" in ko.evidence.ips
            assert len(ko.timeline.important_events) == 1
            assert isinstance(ko.timeline.important_events[0], TimelineEvent)
            assert ko.timeline.important_events[0].action == "Failed Login"
            assert fp.mitre_techniques == ["T1110"]
            assert fp.timeline_hash != ""
            
        await session.commit()

    # Clean up test records
    async with AsyncSessionLocal() as session:
        db_res = await session.execute(select(InvestigationCase).where(InvestigationCase.id == case_id))
        db_case = db_res.scalar_one_or_none()
        if db_case:
            await session.delete(db_case)
        await session.commit()


@pytest.mark.asyncio
async def test_knowledge_builder_builds_knowledge_object_successfully():
    """
    Test B: KnowledgeBuilder successfully builds a valid KnowledgeObject without relationship mocking.
    """
    case_id = uuid.uuid4()
    async with AsyncSessionLocal() as session:
        case = InvestigationCase(
            id=case_id,
            title="Suspicious PowerShell Incident",
            status=InvestigationStatus.RESOLVED,
            severity=Severity.CRITICAL,
            confidence_score=0.95
        )
        session.add(case)
        tech = AttackTechnique(
            case_id=case_id,
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="Execution"
        )
        session.add(tech)
        await session.commit()

    async with AsyncSessionLocal() as session:
        mock_llm_response = json.dumps({
            "summary": "Encoded PowerShell execution detected",
            "executive_summary": "Malicious payload executed via base64 encoded PowerShell command.",
            "attack_type": "Malicious Script Execution",
            "malware_family": None,
            "campaign": "APT-Mock",
            "kill_chain": ["Execution"],
            "important_events": ["Encoded command execution at 02:00 UTC"],
            "attack_story": "Adversary launched encoded PowerShell.",
            "immediate_actions": ["Isolate host"],
            "long_term_actions": ["Restrict PowerShell execution policy"],
            "lessons_learned": "Monitor script block logs."
        })
        
        with patch("services.llm_service.llm_service.generate", new_callable=AsyncMock, return_value=mock_llm_response):
            ko, fp = await knowledge_builder.build(session, case_id)
            assert ko.investigation.title == "Suspicious PowerShell Incident"
            assert ko.attack.mitre_techniques == ["T1059"]
            assert ko.timeline.important_events == ["Encoded command execution at 02:00 UTC"]
            assert fp.campaign == "APT-Mock"
        await session.commit()

    async with AsyncSessionLocal() as session:
        db_res = await session.execute(select(InvestigationCase).where(InvestigationCase.id == case_id))
        db_case = db_res.scalar_one_or_none()
        if db_case:
            await session.delete(db_case)
        await session.commit()


def test_timeline_schema_structured_dictionaries_accepted():
    """
    Test C: Structured dictionaries/objects in important_events are accepted, validated as TimelineEvent,
    and serialized correctly.
    """
    structured_event = {
        "time": "2026-08-23T01:15:00Z",
        "action": "Privilege Escalation",
        "details": "User elevated from Guest to NT AUTHORITY\\SYSTEM",
        "description": "Exploitation of token privilege"
    }
    
    tl = TimelineSection(
        important_events=[structured_event],
        attack_story="Privilege escalation attack flow"
    )
    
    assert len(tl.important_events) == 1
    ev = tl.important_events[0]
    assert isinstance(ev, TimelineEvent)
    assert ev.action == "Privilege Escalation"
    assert ev.time == "2026-08-23T01:15:00Z"
    
    # Test JSON serialization / dumping
    dumped = tl.model_dump(mode="json")
    assert isinstance(dumped["important_events"][0], dict)
    assert dumped["important_events"][0]["action"] == "Privilege Escalation"
    
    # Test roundtrip reconstruction
    reconstructed = TimelineSection(**dumped)
    assert isinstance(reconstructed.important_events[0], TimelineEvent)
    assert reconstructed.important_events[0].action == "Privilege Escalation"


def test_timeline_schema_string_events_compatible():
    """
    Test D: Existing valid string timeline events remain fully supported for backward compatibility.
    """
    string_events = [
        "2026-08-23T01:00:00Z: Initial reconnaissance scan",
        "2026-08-23T01:05:00Z: Brute force login attempts"
    ]
    
    tl = TimelineSection(
        important_events=string_events,
        attack_story="Sequential attack story"
    )
    
    assert len(tl.important_events) == 2
    assert tl.important_events[0] == string_events[0]
    assert isinstance(tl.important_events[0], str)
    
    # Deterministic timeline hash works on strings
    hash_str = _compute_timeline_hash(string_events)
    assert len(hash_str) == 64


def test_timeline_schema_invalid_data_fails_safely():
    """
    Test E: Invalid timeline data fails predictably and safely.
    """
    with pytest.raises(ValidationError):
        # important_events must be a list
        TimelineSection(important_events="not-a-list")

    # Unsupported non-dict, non-string items should fail validation
    with pytest.raises(ValidationError):
        TimelineSection(important_events=[12345])


def test_timeline_rejects_integer_event():
    """Condition 1 regression: integer events are deterministically rejected."""
    with pytest.raises(ValidationError, match="unsupported type"):
        TimelineSection(important_events=["valid string", 12345])


def test_timeline_rejects_boolean_event():
    """Condition 1 regression: boolean events are deterministically rejected."""
    with pytest.raises(ValidationError, match="unsupported type"):
        TimelineSection(important_events=[True])


def test_timeline_rejects_none_event():
    """Condition 1 regression: None events are deterministically rejected."""
    with pytest.raises(ValidationError, match="unsupported type"):
        TimelineSection(important_events=[None])


def test_timeline_rejects_empty_dict_event():
    """Condition 1 regression: empty dict {} produces all-None TimelineEvent and is rejected."""
    with pytest.raises(ValidationError, match="empty TimelineEvent"):
        TimelineSection(important_events=[{}])


def test_timeline_rejects_unrecognized_key_dict():
    """Condition 1 regression: dict with only unrecognized keys produces empty TimelineEvent."""
    with pytest.raises(ValidationError, match="empty TimelineEvent"):
        TimelineSection(important_events=[{"foo": "bar", "baz": 99}])


def test_timeline_accepts_dict_with_at_least_one_recognized_field():
    """Condition 1 regression: dict with at least one recognized field is accepted."""
    tl = TimelineSection(important_events=[{"action": "Login attempt"}])
    assert len(tl.important_events) == 1
    assert isinstance(tl.important_events[0], TimelineEvent)
    assert tl.important_events[0].action == "Login attempt"


@pytest.mark.asyncio
async def test_knowledge_builder_rejects_malformed_llm_timeline_events():
    """
    Condition 1 regression: KnowledgeBuilder raises ValueError when LLM returns
    unsupported timeline event types (e.g. integers) instead of silently discarding.
    """
    case_id = uuid.uuid4()
    async with AsyncSessionLocal() as session:
        case = InvestigationCase(
            id=case_id,
            title="Malformed Timeline Test",
            status=InvestigationStatus.RESOLVED,
            severity=Severity.HIGH,
            confidence_score=0.8
        )
        session.add(case)
        await session.commit()

    async with AsyncSessionLocal() as session:
        mock_llm_response = json.dumps({
            "summary": "Test",
            "executive_summary": "Test",
            "important_events": [12345, {"foo": "bar"}],
            "attack_story": "Test"
        })

        with patch("services.llm_service.llm_service.generate", new_callable=AsyncMock, return_value=mock_llm_response):
            with pytest.raises(ValueError, match="unsupported timeline event type"):
                await knowledge_builder.build(session, case_id)
        await session.commit()

    # Cleanup
    async with AsyncSessionLocal() as session:
        db_res = await session.execute(select(InvestigationCase).where(InvestigationCase.id == case_id))
        db_case = db_res.scalar_one_or_none()
        if db_case:
            await session.delete(db_case)
        await session.commit()


# -----------------------------------------------------------------------------
# Part 5: Condition 2 — Mixed Timeline Event Types Test
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mixed_timeline_events_full_pipeline():
    """
    Condition 2: Verifies the complete lifecycle with mixed event types:
    - structured TimelineEvent (dict)
    - plain string event
    - structured TimelineEvent (dict)
    Validates: parsing, serialization, KnowledgeObject creation, memory indexing,
    memory retrieval, event type preservation, and event field preservation.
    """
    case_id = uuid.uuid4()

    # 1. Create investigation case in PostgreSQL
    async with AsyncSessionLocal() as session:
        case = InvestigationCase(
            id=case_id,
            title="Mixed Timeline Events Test",
            description="Verifies mixed structured/string event handling",
            status=InvestigationStatus.RESOLVED,
            severity=Severity.HIGH,
            confidence_score=0.88
        )
        session.add(case)
        tech = AttackTechnique(
            case_id=case_id,
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="Execution"
        )
        session.add(tech)
        await session.commit()

    # 2. Build KnowledgeObject with mixed events
    async with AsyncSessionLocal() as session:
        mock_llm_response = json.dumps({
            "summary": "Mixed event types incident",
            "executive_summary": "Test mixed events.",
            "attack_type": "Script Execution",
            "campaign": "MixedTest",
            "kill_chain": ["Execution"],
            "important_events": [
                {"time": "2026-08-23T10:00:00Z", "action": "Initial Access", "details": "Phishing link clicked"},
                "2026-08-23T10:05:00Z: PowerShell -enc detected on HOST-01",
                {"time": "2026-08-23T10:10:00Z", "action": "Data Exfiltration", "details": "Staged archive uploaded", "description": "C2 upload"}
            ],
            "attack_story": "Phishing led to script execution and exfil.",
            "immediate_actions": ["Block C2"],
            "long_term_actions": ["Deploy email filtering"],
            "lessons_learned": "Train users on phishing."
        })

        with patch("services.llm_service.llm_service.generate", new_callable=AsyncMock, return_value=mock_llm_response):
            ko, fp = await knowledge_builder.build(session, case_id)

            # Verify parsing: 3 events, correct types
            assert len(ko.timeline.important_events) == 3
            assert isinstance(ko.timeline.important_events[0], TimelineEvent)
            assert isinstance(ko.timeline.important_events[1], str)
            assert isinstance(ko.timeline.important_events[2], TimelineEvent)

            # Verify field preservation on structured events
            assert ko.timeline.important_events[0].time == "2026-08-23T10:00:00Z"
            assert ko.timeline.important_events[0].action == "Initial Access"
            assert ko.timeline.important_events[0].details == "Phishing link clicked"
            assert ko.timeline.important_events[1] == "2026-08-23T10:05:00Z: PowerShell -enc detected on HOST-01"
            assert ko.timeline.important_events[2].action == "Data Exfiltration"
            assert ko.timeline.important_events[2].description == "C2 upload"

            # Verify serialization roundtrip
            dumped = ko.timeline.model_dump(mode="json")
            assert isinstance(dumped["important_events"][0], dict)
            assert isinstance(dumped["important_events"][1], str)
            assert isinstance(dumped["important_events"][2], dict)
            reconstructed = TimelineSection(**dumped)
            assert isinstance(reconstructed.important_events[0], TimelineEvent)
            assert isinstance(reconstructed.important_events[1], str)
            assert isinstance(reconstructed.important_events[2], TimelineEvent)
            assert reconstructed.important_events[2].description == "C2 upload"
        await session.commit()

    # 3. Index into isolated Qdrant collection and PostgreSQL
    test_collection = f"test_mixed_ev_{uuid.uuid4().hex[:8]}"
    test_repo = QdrantRepository(url="http://qdrant:6333", collection_name=test_collection)
    test_mem_svc = InvestigationMemoryService(vector_repo=test_repo)

    async with AsyncSessionLocal() as session:
        await test_mem_svc.initialize()
        await test_mem_svc.index_knowledge(session, ko, fp)

    # 4. Verify PostgreSQL memory archive preserves mixed events
    async with AsyncSessionLocal() as session:
        mem_res = await session.execute(
            select(InvestigationMemory).where(
                (InvestigationMemory.investigation_id == case_id) &
                (InvestigationMemory.is_latest == True)
            )
        )
        mem = mem_res.scalar_one_or_none()
        assert mem is not None
        stored_events = mem.knowledge_object["timeline"]["important_events"]
        assert len(stored_events) == 3
        assert isinstance(stored_events[0], dict)  # Structured → dict in JSON
        assert isinstance(stored_events[1], str)    # String preserved
        assert isinstance(stored_events[2], dict)   # Structured → dict in JSON
        assert stored_events[0]["action"] == "Initial Access"
        assert stored_events[2]["description"] == "C2 upload"
        await session.commit()

    # 5. Retrieve from memory and verify reconstruction
    async with AsyncSessionLocal() as session:
        query_fp = InvestigationFingerprint(
            attack_type="Script Execution",
            mitre_techniques=["T1059"],
            campaign="MixedTest",
            risk_score=0.88,
            ioc_hash=fp.ioc_hash,
            timeline_hash=fp.timeline_hash
        )
        similar = await test_mem_svc.find_similar_cases(session, query_fp, "Mixed event types incident", limit=3)
        assert len(similar) >= 1
        match = next((s for s in similar if s.investigation_id == str(case_id)), None)
        assert match is not None

        rko = match.knowledge_object
        assert rko is not None
        assert len(rko.timeline.important_events) == 3
        # After retrieval reconstruction, verify type preservation
        assert isinstance(rko.timeline.important_events[0], TimelineEvent)
        assert isinstance(rko.timeline.important_events[1], str)
        assert isinstance(rko.timeline.important_events[2], TimelineEvent)
        # Field preservation after full roundtrip
        assert rko.timeline.important_events[0].action == "Initial Access"
        assert rko.timeline.important_events[2].description == "C2 upload"
        await session.commit()

    # 6. Cleanup
    async with AsyncSessionLocal() as session:
        mem_del = await session.execute(
            select(InvestigationMemory).where(InvestigationMemory.investigation_id == case_id)
        )
        for m in mem_del.scalars().all():
            await session.delete(m)
        db_res = await session.execute(select(InvestigationCase).where(InvestigationCase.id == case_id))
        db_case = db_res.scalar_one_or_none()
        if db_case:
            await session.delete(db_case)
        await session.commit()

    try:
        await test_repo.qdrant.delete_collection(test_collection)
    except Exception:
        pass


# -----------------------------------------------------------------------------
# Part 6: Condition 3 — Celery Broker Dispatch Integration Test
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_celery_broker_dispatch_memory_indexing():
    """
    Condition 3: Verifies the Redis broker → Celery worker → memory indexing path.

    The task is sent via .delay() through a real Redis broker (isolated test DB 15)
    to a real Celery worker running in-process against the test database and test
    Qdrant collection, then PostgreSQL is polled for the InvestigationMemory record
    that the worker should create. The development worker is never involved.
    """
    from workers.tasks.memory_tasks import index_resolved_investigation_task
    from tests.support.celery import running_test_worker
    import asyncio

    case_id = uuid.uuid4()

    # 1. Create a resolved investigation in PostgreSQL
    async with AsyncSessionLocal() as session:
        case = InvestigationCase(
            id=case_id,
            title="Celery Broker Integration Test",
            description="Verifies API → Redis → Celery → memory indexing dispatch",
            status=InvestigationStatus.RESOLVED,
            severity=Severity.HIGH,
            confidence_score=0.90
        )
        session.add(case)
        tech = AttackTechnique(
            case_id=case_id,
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            confidence=0.9
        )
        session.add(tech)
        ev = EvidenceItem(
            case_id=case_id,
            evidence_type="ip",
            source="firewall",
            timestamp=datetime.now(timezone.utc),
            artifact="10.0.0.99",
            reason="Source of brute force attempts"
        )
        session.add(ev)
        await session.commit()

    mock_llm_response = json.dumps({
        "summary": "Celery Broker Integration Test summary",
        "executive_summary": "Brute force source 10.0.0.99 recorded.",
        "important_events": ["Brute force attempts from 10.0.0.99"],
    })

    # 2. Dispatch task through the isolated Redis broker to an in-process worker
    max_wait_seconds = 120
    poll_interval = 2
    elapsed = 0
    memory_created = False

    global_vector_repo_before = memory_service.vector_repo

    with patch("services.llm_service.llm_service.generate", new_callable=AsyncMock, return_value=mock_llm_response):
        with running_test_worker():
            result = index_resolved_investigation_task.delay(str(case_id))

            # 3. Wait for Celery worker to process (poll with timeout)
            while elapsed < max_wait_seconds:
                await asyncio.sleep(poll_interval)
                elapsed += poll_interval
                async with AsyncSessionLocal() as session:
                    mem_res = await session.execute(
                        select(InvestigationMemory).where(
                            InvestigationMemory.investigation_id == case_id
                        )
                    )
                    mem = mem_res.scalar_one_or_none()
                    if mem is not None:
                        memory_created = True
                        break

    # The task must not replace the process-global Qdrant client (bound to another event loop)
    assert memory_service.vector_repo is global_vector_repo_before

    # 4. Verify the memory record was created by the Celery worker
    assert memory_created, (
        f"Celery worker did not create InvestigationMemory for case {case_id} "
        f"within {max_wait_seconds}s. Celery task result state: {result.state}"
    )

    async with AsyncSessionLocal() as session:
        mem_res = await session.execute(
            select(InvestigationMemory).where(
                InvestigationMemory.investigation_id == case_id
            )
        )
        mem = mem_res.scalar_one_or_none()
        assert mem is not None
        assert mem.is_latest is True
        assert mem.knowledge_version == 1
        assert mem.qdrant_id is not None
        assert mem.knowledge_object["investigation"]["title"] == "Celery Broker Integration Test"
        await session.commit()

    # 5. Cleanup
    async with AsyncSessionLocal() as session:
        mem_del = await session.execute(
            select(InvestigationMemory).where(InvestigationMemory.investigation_id == case_id)
        )
        for m in mem_del.scalars().all():
            await session.delete(m)
        db_res = await session.execute(select(InvestigationCase).where(InvestigationCase.id == case_id))
        db_case = db_res.scalar_one_or_none()
        if db_case:
            await session.delete(db_case)
        await session.commit()


# Part 4: Real End-to-End Memory Pipeline Integration Test
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_memory_pipeline_end_to_end_full_flow():
    """
    Comprehensive End-to-End Memory Pipeline Test:
    1. Real PostgreSQL database: Persists reviewed/resolved InvestigationCase with relationships.
    2. KnowledgeBuilder: Loads case asynchronously, produces valid KnowledgeObject & Fingerprint.
    3. MemoryService: Indexes into real Qdrant vector database (unmocked) and archives in PostgreSQL.
    4. Retrieval: Queries memory through find_similar_cases and reconstructs full KnowledgeObject.
    """
    case_id = uuid.uuid4()
    exec_id = uuid.uuid4()
    
    # 1. Setup realistic resolved investigation in PostgreSQL
    async with AsyncSessionLocal() as session:
        case = InvestigationCase(
            id=case_id,
            title="E2E Real Memory Pipeline Attack",
            description="End-to-end integration verification case for vector memory",
            status=InvestigationStatus.RESOLVED,
            severity=Severity.HIGH,
            confidence_score=0.92
        )
        session.add(case)
        
        tech = AttackTechnique(
            case_id=case_id,
            technique_id="T1068",
            technique_name="Exploitation for Privilege Escalation",
            tactic="Privilege Escalation",
            confidence=1.0
        )
        session.add(tech)
        
        ev1 = EvidenceItem(
            case_id=case_id,
            evidence_type="ip",
            source="suricata",
            timestamp=datetime.now(timezone.utc),
            artifact="203.0.113.88",
            reason="C2 callback destination"
        )
        session.add(ev1)
        
        ev2 = EvidenceItem(
            case_id=case_id,
            evidence_type="hash",
            source="sysmon",
            timestamp=datetime.now(timezone.utc),
            artifact="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            reason="Malicious payload binary hash"
        )
        session.add(ev2)
        
        execution = AgentExecution(
            id=exec_id,
            investigation_id=case_id,
            agent_name="Threat Intel Analyst",
            status="completed",
            confidence=0.95
        )
        session.add(execution)
        
        step = AgentReasoningStep(
            execution_id=exec_id,
            step_type="decision_made",
            content={"text": "Confirmed local privilege escalation via kernel vulnerability."}
        )
        session.add(step)
        await session.commit()

    # 2. Run KnowledgeBuilder to produce KnowledgeObject
    async with AsyncSessionLocal() as session:
        mock_llm_response = json.dumps({
            "summary": "Kernel privilege escalation exploit followed by C2 beaconing",
            "executive_summary": "Adversary gained initial access and escalated to SYSTEM using CVE-2026-MOCK.",
            "attack_type": "Privilege Escalation",
            "malware_family": "MockRat",
            "campaign": "Operation MemoryTest",
            "kill_chain": ["Privilege Escalation", "Command and Control"],
            "important_events": [
                {"time": "2026-08-23T01:20:00Z", "action": "Vulnerability Triggered", "details": "Exploit executed on target"},
                {"time": "2026-08-23T01:25:00Z", "action": "C2 Established", "details": "Beaconed to 203.0.113.88"}
            ],
            "attack_story": "Exploit binary executed to gain SYSTEM, followed by C2 connection.",
            "immediate_actions": ["Patch kernel", "Block C2 IP 203.0.113.88"],
            "long_term_actions": ["Deploy EDR behavioral prevention"],
            "lessons_learned": "Ensure rapid patch cycle for privilege escalation CVEs."
        })
        
        with patch("services.llm_service.llm_service.generate", new_callable=AsyncMock, return_value=mock_llm_response):
            knowledge_obj, fingerprint = await knowledge_builder.build(session, case_id)
            
            assert knowledge_obj.investigation.title == "E2E Real Memory Pipeline Attack"
            assert knowledge_obj.attack.attack_type == "Privilege Escalation"
            assert "T1068" in knowledge_obj.attack.mitre_techniques
            assert "203.0.113.88" in knowledge_obj.evidence.ips
            assert len(knowledge_obj.timeline.important_events) == 2
        await session.commit()

    # 3. Index KnowledgeObject into Qdrant & PostgreSQL Archive using isolated test collection
    test_collection = f"test_e2e_mem_{uuid.uuid4().hex[:8]}"
    test_repo = QdrantRepository(url="http://qdrant:6333", collection_name=test_collection)
    test_memory_service = InvestigationMemoryService(vector_repo=test_repo)
    
    async with AsyncSessionLocal() as session:
        await test_memory_service.initialize()
        await test_memory_service.index_knowledge(session, knowledge_obj, fingerprint)

    # 4. Verify PostgreSQL InvestigationMemory record exists and is_latest=True
    async with AsyncSessionLocal() as session:
        mem_res = await session.execute(
            select(InvestigationMemory).where(
                (InvestigationMemory.investigation_id == case_id) &
                (InvestigationMemory.is_latest == True)
            )
        )
        mem_record = mem_res.scalar_one_or_none()
        assert mem_record is not None
        assert mem_record.knowledge_version == 1
        assert mem_record.qdrant_id is not None
        assert mem_record.knowledge_object["investigation"]["title"] == "E2E Real Memory Pipeline Attack"
        assert mem_record.knowledge_object["attack"]["attack_type"] == "Privilege Escalation"
        await session.commit()

    # 5. Query Memory via find_similar_cases and verify full reconstruction
    async with AsyncSessionLocal() as session:
        query_fp = InvestigationFingerprint(
            attack_type="Privilege Escalation",
            mitre_techniques=["T1068"],
            campaign="Operation MemoryTest",
            risk_score=0.9,
            ioc_hash=fingerprint.ioc_hash,
            timeline_hash=fingerprint.timeline_hash
        )
        
        query_summary = "Privilege escalation kernel exploit with C2 beaconing"
        similar = await test_memory_service.find_similar_cases(session, query_fp, query_summary, limit=3)
        
        assert len(similar) >= 1
        top_match = next((s for s in similar if s.investigation_id == str(case_id)), None)
        assert top_match is not None
        assert top_match.similarity_score > 0.8
        assert top_match.mitre_overlap_score == 1.0
        assert top_match.ioc_overlap_score == 1.0
        assert top_match.attack_type_match is True
        assert top_match.campaign_match is True
        
        # Verify reconstructed KnowledgeObject inside SimilarityResult
        reconstructed_ko = top_match.knowledge_object
        assert reconstructed_ko is not None
        assert reconstructed_ko.investigation.title == "E2E Real Memory Pipeline Attack"
        assert reconstructed_ko.attack.attack_type == "Privilege Escalation"
        assert len(reconstructed_ko.timeline.important_events) == 2
        assert isinstance(reconstructed_ko.timeline.important_events[0], TimelineEvent)
        await session.commit()

    # 6. Cleanup test records
    async with AsyncSessionLocal() as session:
        # Delete memory archive record
        mem_del = await session.execute(
            select(InvestigationMemory).where(InvestigationMemory.investigation_id == case_id)
        )
        for m in mem_del.scalars().all():
            await session.delete(m)
            
        # Delete case
        db_res = await session.execute(select(InvestigationCase).where(InvestigationCase.id == case_id))
        db_case = db_res.scalar_one_or_none()
        if db_case:
            await session.delete(db_case)
        await session.commit()

    # Clean up isolated Qdrant test collection
    try:
        await test_repo.qdrant.delete_collection(test_collection)
    except Exception:
        pass
