from typing import List, Dict, Any, Optional, Set
from pydantic import BaseModel, Field
from datetime import datetime
import uuid

class GroundTruthScenario(BaseModel):
    scenario_id: str
    category: str  # BENIGN, CLEAR_INCIDENT, AMBIGUOUS, MULTI_STAGE, CONCURRENT, ADVERSARIAL
    description: str
    telemetry_source: str = "yarox-synthetic-lab"
    telemetry_events: List[Dict[str, Any]]
    expected_detection: bool
    expected_case_count: int = 1
    expected_attack_type: Optional[str] = None
    expected_severity: Optional[str] = None  # LOW, MEDIUM, HIGH, CRITICAL
    expected_severity_floor: Optional[str] = None
    expected_entities: Dict[str, List[str]] = Field(default_factory=lambda: {"users": [], "hosts": [], "ips": [], "processes": []})
    expected_evidence_count_min: int = 0
    expected_mitre_techniques: List[str] = Field(default_factory=list)
    expected_recommendation_concepts: List[str] = Field(default_factory=list)
    memory_condition: str = "NO_PRIOR_MEMORY"
    expected_memory_behavior: Optional[str] = None
    expected_confidence_min: float = 0.0
    expected_confidence_max: float = 1.0
    security_test_type: Optional[str] = None  # PROMPT_INJECTION, TAG_BREAKOUT, HALLUCINATION, NONE

class HardGateResult(BaseModel):
    gate_name: str
    passed: bool
    details: str

class DetectionMetrics(BaseModel):
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    detection_recall: float = 0.0
    false_positive_rate: float = 0.0
    case_count_accuracy: float = 0.0
    correlation_accuracy: float = 0.0

class InvestigationMetrics(BaseModel):
    severity_accuracy: float = 0.0
    evidence_precision: float = 0.0
    evidence_recall: float = 0.0
    timeline_chronology_accuracy: float = 0.0
    timeline_completeness: float = 0.0
    mitre_precision: float = 0.0
    mitre_recall: float = 0.0
    invalid_mitre_count: int = 0
    recommendation_coverage: float = 0.0
    average_confidence: float = 0.0

class SafetyMetrics(BaseModel):
    prompt_injection_resistance: float = 1.0  # 1.0 = 100%
    hallucinated_entity_count: int = 0
    hallucinated_event_count: int = 0
    invalid_mitre_technique_count: int = 0
    memory_poisoning_events: int = 0
    cross_case_contamination_events: int = 0
    simulation_integrity_violations: int = 0

class ScenarioEvaluationResult(BaseModel):
    scenario_id: str
    category: str
    passed: bool
    detection_matched: bool
    case_count_matched: bool
    severity_matched: bool
    mitre_matched: bool
    timeline_accurate: bool
    evidence_accurate: bool
    safety_passed: bool
    actual_severity: Optional[str] = None
    actual_mitre_techniques: List[str] = Field(default_factory=list)
    actual_confidence: Optional[float] = None
    composite_score: float = 0.0
    findings: List[str] = Field(default_factory=list)
    hard_gate_failures: List[str] = Field(default_factory=list)
    execution_time_seconds: float = 0.0

class BenchmarkRunResult(BaseModel):
    suite_name: str = "core_v1"
    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    yarox_version: str = "0.2.0"
    git_commit: Optional[str] = None
    model_name: str = "llama3.1"
    environment: str = "development"
    total_scenarios: int = 0
    scenarios_passed: int = 0
    scenarios_failed: int = 0
    runtime_seconds: float = 0.0
    
    # Four distinct result layers
    detection_metrics: DetectionMetrics = Field(default_factory=DetectionMetrics)
    investigation_metrics: InvestigationMetrics = Field(default_factory=InvestigationMetrics)
    safety_metrics: SafetyMetrics = Field(default_factory=SafetyMetrics)
    
    composite_investigation_score: float = 0.0  # 0 to 100
    hard_gates: List[HardGateResult] = Field(default_factory=list)
    overall_status: str = "FAIL"  # PASS or FAIL (hard gates dictate outcome)
    
    scenario_results: List[ScenarioEvaluationResult] = Field(default_factory=list)
    limitations_note: str = (
        "Note: The Phase 4C core_v1 benchmark is a developmental baseline suite consisting of 12 controlled synthetic scenarios. "
        "It evaluates correctness against deterministic ground truth and does not represent statistically significant production enterprise SOC benchmarks."
    )

class ComparisonResult(BaseModel):
    baseline_run_id: str
    candidate_run_id: str
    baseline_score: float
    candidate_score: float
    score_delta: float
    overall_status_change: str  # IMPROVED, REGRESSED, UNCHANGED
    metric_diffs: Dict[str, float]
    new_hard_gate_failures: List[str]
    resolved_hard_gate_failures: List[str]
    scenario_regressions: List[str]
    scenario_improvements: List[str]
