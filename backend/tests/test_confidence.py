"""
Confidence scoring: deterministic, component-based, derived from persisted data.
"""
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import select

from agents.orchestrator import AgentOrchestrator
from database.session import AsyncSessionLocal
from models.investigation import AgentExecution, InvestigationCase, InvestigationReport
from scoring.confidence import WEIGHTS, ConfidenceInputs, calculate_confidence
from services.confidence_service import acceptance_confidence, collect_confidence_inputs
from tests.support.llm_double import EvidenceCitingLLM
from tests.test_report_persistence import _create_detected_case

FULL = ConfidenceInputs(
    severity="CRITICAL", agents_total=4, agents_completed=4,
    evidence_total=4, evidence_cited=4, distinct_source_events=3, distinct_sources=2,
    evidence_with_verified_hash=4, memory_top_similarity=1.0,
)
EMPTY = ConfidenceInputs(
    severity=None, agents_total=4, agents_completed=0,
    evidence_total=0, evidence_cited=0, distinct_source_events=0, distinct_sources=0,
    evidence_with_verified_hash=0, memory_top_similarity=None,
)


def test_weights_sum_to_one():
    assert round(sum(WEIGHTS.values()), 6) == 1.0


def test_best_case_scores_one_and_empty_case_scores_zero():
    assert calculate_confidence(FULL).score == 1.0
    assert calculate_confidence(EMPTY).score == 0.0


def test_score_is_deterministic():
    assert calculate_confidence(FULL).score == calculate_confidence(FULL).score


def test_breakdown_explains_the_score():
    result = calculate_confidence(FULL)
    assert round(sum(c.contribution for c in result.components), 4) == result.score
    assert {c.name for c in result.components} == set(WEIGHTS)
    for component in result.components:
        assert component.detail
        assert component.contribution == round(component.value * component.weight, 4)


def test_no_hardcoded_075():
    """The old engine returned 0.75 for almost every case; the score must now move with inputs."""
    scores = set()
    for completed in range(5):
        for evidence in (0, 1, 5):
            inputs = ConfidenceInputs(
                severity="HIGH", agents_total=4, agents_completed=completed,
                evidence_total=evidence, evidence_cited=evidence, distinct_source_events=evidence,
                distinct_sources=min(evidence, 2), evidence_with_verified_hash=evidence,
                memory_top_similarity=None,
            )
            scores.add(calculate_confidence(inputs).score)
    assert len(scores) > 5


def test_degraded_agents_lower_the_score():
    def score(completed):
        return calculate_confidence(ConfidenceInputs(
            severity="HIGH", agents_total=4, agents_completed=completed,
            evidence_total=2, evidence_cited=2, distinct_source_events=2, distinct_sources=1,
            evidence_with_verified_hash=2, memory_top_similarity=None,
        )).score

    assert score(4) > score(2) > score(0)
    assert round(score(4) - score(2), 4) == round(WEIGHTS["agent_completion"] * 0.5, 4)


def test_uncited_evidence_lowers_coverage():
    def score(cited):
        return calculate_confidence(ConfidenceInputs(
            severity="HIGH", agents_total=4, agents_completed=4,
            evidence_total=4, evidence_cited=cited, distinct_source_events=2, distinct_sources=1,
            evidence_with_verified_hash=4, memory_top_similarity=None,
        )).score

    assert score(4) > score(1)


def test_severity_and_memory_components_behave():
    def score(severity, memory):
        return calculate_confidence(ConfidenceInputs(
            severity=severity, agents_total=4, agents_completed=4,
            evidence_total=2, evidence_cited=2, distinct_source_events=2, distinct_sources=2,
            evidence_with_verified_hash=2, memory_top_similarity=memory,
        )).score

    assert score("CRITICAL", None) > score("LOW", None)
    assert score("HIGH", 0.9) > score("HIGH", None)
    assert score("NONSENSE", None) < score("LOW", None)


def test_unverified_evidence_lowers_integrity_component():
    verified = calculate_confidence(ConfidenceInputs(
        severity="HIGH", agents_total=4, agents_completed=4, evidence_total=2, evidence_cited=2,
        distinct_source_events=2, distinct_sources=1, evidence_with_verified_hash=2, memory_top_similarity=None,
    ))
    unverified = calculate_confidence(ConfidenceInputs(
        severity="HIGH", agents_total=4, agents_completed=4, evidence_total=2, evidence_cited=2,
        distinct_source_events=2, distinct_sources=1, evidence_with_verified_hash=0, memory_top_similarity=None,
    ))
    assert round(verified.score - unverified.score, 4) == WEIGHTS["evidence_integrity"]


@pytest.mark.parametrize("accepted,rejected,expected", [
    (3, 0, 1.0), (1, 1, 0.5), (0, 2, 0.0), (0, 0, None),
])
def test_agent_acceptance_confidence(accepted, rejected, expected):
    assert acceptance_confidence(accepted, rejected) == expected


# ---------------------------------------------------------------- against real data

@pytest.mark.asyncio
async def test_inputs_are_collected_from_persisted_investigation_state():
    case_id, event_id = await _create_detected_case()
    llm = EvidenceCitingLLM()
    orchestrator = AgentOrchestrator()
    with patch("services.llm_service.llm_service.generate", side_effect=llm.generate):
        async with AsyncSessionLocal() as session:
            await orchestrator.run_investigation(session, str(case_id))

    async with AsyncSessionLocal() as session:
        inputs = await collect_confidence_inputs(
            session, case_id, severity="HIGH",
            agent_statuses={
                "Triage Analyst": "completed", "Forensic Timeline Analyst": "completed",
                "Threat Intel Analyst": "completed", "SOC Lead": "completed",
            },
            memory_top_similarity=None,
        )
        case = await session.get(InvestigationCase, case_id)
        report = (await session.execute(
            select(InvestigationReport).where(InvestigationReport.case_id == case_id)
        )).scalar_one()

    assert inputs.evidence_total >= 1
    assert inputs.evidence_cited >= 1              # findings cited real evidence
    assert inputs.distinct_source_events >= 1
    assert inputs.evidence_with_verified_hash == inputs.evidence_total  # hashes verify
    assert inputs.agents_completed == 4

    # The case carries a computed score with an auditable breakdown
    assert case.confidence_score == report.confidence_score
    names = {c["name"] for c in case.confidence_breakdown}
    assert names == set(WEIGHTS)
    assert round(sum(c["contribution"] for c in case.confidence_breakdown), 4) == case.confidence_score
    assert case.confidence_score != 0.75


@pytest.mark.asyncio
async def test_agent_execution_confidence_reflects_validation_outcome():
    case_id, _ = await _create_detected_case()
    llm = EvidenceCitingLLM()  # the triage response includes one fabricated citation
    orchestrator = AgentOrchestrator()
    with patch("services.llm_service.llm_service.generate", side_effect=llm.generate):
        async with AsyncSessionLocal() as session:
            await orchestrator.run_investigation(session, str(case_id))

    async with AsyncSessionLocal() as session:
        executions = {
            e.agent_name: e for e in (await session.execute(
                select(AgentExecution).where(AgentExecution.investigation_id == case_id)
            )).scalars().all()
        }

    triage = executions["Triage Analyst"]
    assert triage.confidence == 0.5  # 1 of 2 proposed findings survived validation
    assert triage.confidence_explanation["accepted_findings"] == 1
    assert triage.confidence_explanation["rejected_findings"] == 1

    timeline = executions["Forensic Timeline Analyst"]
    assert timeline.confidence == 1.0  # all proposed findings valid

    # The Memory Agent produces no findings, so it claims no confidence
    memory = executions["Memory Agent"]
    assert memory.confidence is None
    assert "memory retrieval" in memory.confidence_explanation["basis"]
