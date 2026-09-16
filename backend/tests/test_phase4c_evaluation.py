import pytest
import os
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock

from evaluation.schemas import (
    GroundTruthScenario,
    ScenarioEvaluationResult,
    BenchmarkRunResult,
    DetectionMetrics,
    InvestigationMetrics,
    SafetyMetrics,
    HardGateResult,
    ComparisonResult
)
from evaluation.runner import EvaluationRunner
from evaluation.metrics import metrics_engine
from evaluation.scorer import scorer
from evaluation.agent_eval import agent_evaluator
from evaluation.comparator import EvaluationComparator


# -----------------------------------------------------------------------------
# 1. Ground Truth Catalog & Schema Tests
# -----------------------------------------------------------------------------
def test_ground_truth_catalog_loading():
    runner = EvaluationRunner()
    scenarios = runner.load_ground_truth()
    
    assert len(scenarios) == 12
    categories = set(s.category for s in scenarios)
    assert "BENIGN" in categories
    assert "CLEAR_INCIDENT" in categories
    assert "AMBIGUOUS" in categories
    assert "MULTI_STAGE" in categories
    assert "CONCURRENT" in categories
    assert "ADVERSARIAL" in categories


def test_ground_truth_scenarios_have_valid_structure():
    runner = EvaluationRunner()
    scenarios = runner.load_ground_truth()
    
    for s in scenarios:
        assert s.scenario_id is not None
        assert len(s.telemetry_events) > 0
        assert s.telemetry_source == "yarox-synthetic-lab"
        for ev in s.telemetry_events:
            assert ev["source"] == "yarox-synthetic-lab"
            assert ev["metadata"]["telemetry_type"] == "SYNTHETIC_TEST"
            assert ev["metadata"]["lab"] is True


# -----------------------------------------------------------------------------
# 2. Metric Calculations Tests
# -----------------------------------------------------------------------------
def test_detection_metrics_calculation():
    scenarios = [
        GroundTruthScenario(scenario_id="s1", category="BENIGN", description="d", telemetry_events=[], expected_detection=False, expected_case_count=0),
        GroundTruthScenario(scenario_id="s2", category="CLEAR_INCIDENT", description="d", telemetry_events=[], expected_detection=True, expected_case_count=1),
    ]
    results = [
        ScenarioEvaluationResult(scenario_id="s1", category="BENIGN", passed=True, detection_matched=True, case_count_matched=True, severity_matched=True, mitre_matched=True, timeline_accurate=True, evidence_accurate=True, safety_passed=True),
        ScenarioEvaluationResult(scenario_id="s2", category="CLEAR_INCIDENT", passed=True, detection_matched=True, case_count_matched=True, severity_matched=True, mitre_matched=True, timeline_accurate=True, evidence_accurate=True, safety_passed=True, actual_severity="HIGH"),
    ]
    
    metrics = metrics_engine.calculate_detection_metrics(scenarios, results)
    assert metrics.true_positives == 1
    assert metrics.true_negatives == 1
    assert metrics.false_positives == 0
    assert metrics.false_negatives == 0
    assert metrics.detection_recall == 1.0
    assert metrics.false_positive_rate == 0.0


def test_investigation_metrics_mitre_precision():
    scenarios = [
        GroundTruthScenario(
            scenario_id="s1", category="CLEAR_INCIDENT", description="d", telemetry_events=[],
            expected_detection=True, expected_case_count=1, expected_mitre_techniques=["T1059", "T1110"]
        )
    ]
    # YAROX matched T1059 and T1110 correctly
    results = [
        ScenarioEvaluationResult(
            scenario_id="s1", category="CLEAR_INCIDENT", passed=True, detection_matched=True,
            case_count_matched=True, severity_matched=True, mitre_matched=True, timeline_accurate=True,
            evidence_accurate=True, safety_passed=True, actual_mitre_techniques=["T1059", "T1110"],
            actual_severity="HIGH"
        )
    ]
    metrics = metrics_engine.calculate_investigation_metrics(scenarios, results)
    assert metrics.mitre_precision == 1.0
    assert metrics.mitre_recall == 1.0
    assert metrics.invalid_mitre_count == 0


# -----------------------------------------------------------------------------
# 3. Composite Score & Hard Gates Tests
# -----------------------------------------------------------------------------
def test_composite_score_calculation():
    det = DetectionMetrics(detection_recall=1.0, false_positive_rate=0.0, correlation_accuracy=1.0)
    inv = InvestigationMetrics(severity_accuracy=1.0, mitre_precision=1.0, mitre_recall=1.0, timeline_chronology_accuracy=1.0, evidence_precision=1.0, recommendation_coverage=1.0)
    safety = SafetyMetrics(prompt_injection_resistance=1.0)
    
    score = scorer.calculate_composite_score(det, inv, safety)
    assert score == 100.0


def test_hard_gate_failure_overrides_high_composite_score():
    """
    Verifies that even if a composite score is 95, a failed hard gate (e.g. Prompt Injection) marks overall status as FAIL.
    """
    det = DetectionMetrics(detection_recall=1.0, false_positive_rate=0.0, correlation_accuracy=1.0)
    inv = InvestigationMetrics(severity_accuracy=1.0, mitre_precision=1.0, mitre_recall=1.0, timeline_chronology_accuracy=1.0, evidence_precision=1.0, recommendation_coverage=1.0)
    
    # Simulate prompt injection failure (0.50 resistance instead of 1.0)
    safety = SafetyMetrics(prompt_injection_resistance=0.5)
    
    score = scorer.calculate_composite_score(det, inv, safety)
    assert score >= 90.0  # High score
    
    gates, overall_passed = scorer.evaluate_hard_gates(det, inv, safety)
    assert not overall_passed  # Hard gate MUST fail
    assert any(g.gate_name.startswith("Gate 1") and not g.passed for g in gates)


# -----------------------------------------------------------------------------
# 4. Agent-Level Evaluator Unit Tests
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_agent_evaluator_triage_guardrail():
    res = await agent_evaluator.evaluate_triage_guardrails()
    assert res["passed"] is True
    assert res["assigned_severity"] in ("MEDIUM", "HIGH", "CRITICAL")


@pytest.mark.asyncio
async def test_agent_evaluator_threat_intel_mitre_validation():
    res = await agent_evaluator.evaluate_threat_intel_kb_validation()
    assert res["passed"] is True
    assert "T1059" in res["retained_techniques"]
    assert "T9999_FAKE" not in res["retained_techniques"]


@pytest.mark.asyncio
async def test_agent_evaluator_timeline_ordering():
    res = await agent_evaluator.evaluate_timeline_ordering()
    assert res["passed"] is True
    assert res["event_count"] == 2


@pytest.mark.asyncio
async def test_agent_evaluator_report_recommendations():
    res = await agent_evaluator.evaluate_report_recommendations()
    assert res["passed"] is True
    assert res["recommendations_count"] == 3


# -----------------------------------------------------------------------------
# 5. Benchmark Comparator Tests
# -----------------------------------------------------------------------------
def test_comparator_detects_regression_and_improvements():
    base_run = BenchmarkRunResult(
        composite_investigation_score=80.0,
        overall_status="PASS",
        hard_gates=[HardGateResult(gate_name="Gate 1", passed=True, details="OK")],
        scenario_results=[ScenarioEvaluationResult(scenario_id="s1", category="BENIGN", passed=True, detection_matched=True, case_count_matched=True, severity_matched=True, mitre_matched=True, timeline_accurate=True, evidence_accurate=True, safety_passed=True)]
    )
    
    # Candidate breaks a hard gate
    cand_run = BenchmarkRunResult(
        composite_investigation_score=85.0,
        overall_status="FAIL",
        hard_gates=[HardGateResult(gate_name="Gate 1", passed=False, details="Failed")],
        scenario_results=[ScenarioEvaluationResult(scenario_id="s1", category="BENIGN", passed=False, detection_matched=False, case_count_matched=True, severity_matched=True, mitre_matched=True, timeline_accurate=True, evidence_accurate=True, safety_passed=True)]
    )
    
    diff = EvaluationComparator.compare_runs(base_run, cand_run)
    assert diff.overall_status_change == "REGRESSED"
    assert "Gate 1" in diff.new_hard_gate_failures
    assert "s1" in diff.scenario_regressions
