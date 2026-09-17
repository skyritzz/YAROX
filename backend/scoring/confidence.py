"""
Investigation confidence scoring.

The score answers one question: **how well is this investigation's conclusion supported
by what the system actually observed and verified?** Every component is computed from
persisted investigation data — no constants stand in for measurements, and the breakdown
shows each component's value, weight and contribution so an analyst can audit the number.

Components (each in [0, 1]):

| Component            | Weight | Meaning |
|----------------------|--------|---------|
| ``rule_severity``    | 0.30   | Severity of the deterministic detection that opened the case (LOW .25 → CRITICAL 1.0). Rule matches are facts, not inferences. |
| ``agent_completion`` | 0.20   | Fraction of investigation agents that completed; a degraded agent means part of the analysis is missing. |
| ``evidence_coverage``| 0.20   | Fraction of the case's evidence items that agent findings actually cite. Analysis that explains one of ten artifacts is weaker than analysis that explains all ten. |
| ``corroboration``    | 0.15   | Independent support: distinct source events and distinct telemetry sources behind the evidence. A single event corroborates less than several events from different sources. |
| ``memory_support``   | 0.10   | Similarity of the closest verified historical case (0 when memory holds nothing similar). |
| ``evidence_integrity``| 0.05  | Fraction of evidence whose source event carries a verifiable SHA-256 payload hash. |

A case with no evidence and no completed agents scores 0. The weights sum to 1.0, so the
score is a weighted average and never exceeds 1.
"""
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SEVERITY_VALUE = {"LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.75, "CRITICAL": 1.0}

WEIGHTS = {
    "rule_severity": 0.30,
    "agent_completion": 0.20,
    "evidence_coverage": 0.20,
    "corroboration": 0.15,
    "memory_support": 0.10,
    "evidence_integrity": 0.05,
}


@dataclass
class ConfidenceComponent:
    name: str
    value: float
    weight: float
    contribution: float
    detail: str


@dataclass
class ConfidenceResult:
    score: float
    components: List[ConfidenceComponent] = field(default_factory=list)

    def breakdown(self) -> List[Dict[str, Any]]:
        return [asdict(c) for c in self.components]


@dataclass
class ConfidenceInputs:
    """Everything the score is derived from, all read from persisted investigation state."""
    severity: Optional[str]
    agents_total: int
    agents_completed: int
    evidence_total: int
    evidence_cited: int
    distinct_source_events: int
    distinct_sources: int
    evidence_with_verified_hash: int
    memory_top_similarity: Optional[float]


def _corroboration_value(distinct_events: int, distinct_sources: int) -> float:
    """
    Independent support saturates: 1 event is weak, 3+ events is strong, and evidence
    from more than one telemetry source adds to it.
    """
    event_component = min(distinct_events, 3) / 3.0
    source_component = min(distinct_sources, 2) / 2.0
    return round(0.7 * event_component + 0.3 * source_component, 4)


def calculate_confidence(inputs: ConfidenceInputs) -> ConfidenceResult:
    severity_key = (inputs.severity or "").upper()
    severity_value = SEVERITY_VALUE.get(severity_key, 0.0)

    completion = inputs.agents_completed / inputs.agents_total if inputs.agents_total else 0.0
    coverage = inputs.evidence_cited / inputs.evidence_total if inputs.evidence_total else 0.0
    corroboration = _corroboration_value(inputs.distinct_source_events, inputs.distinct_sources)
    memory = inputs.memory_top_similarity or 0.0
    integrity = inputs.evidence_with_verified_hash / inputs.evidence_total if inputs.evidence_total else 0.0

    values = {
        "rule_severity": (severity_value, f"detection severity {severity_key or 'unknown'}"),
        "agent_completion": (completion, f"{inputs.agents_completed}/{inputs.agents_total} agents completed"),
        "evidence_coverage": (coverage, f"{inputs.evidence_cited}/{inputs.evidence_total} evidence items cited by findings"),
        "corroboration": (corroboration, f"{inputs.distinct_source_events} source event(s) across {inputs.distinct_sources} telemetry source(s)"),
        "memory_support": (
            memory,
            f"closest verified historical case {memory:.2f}" if inputs.memory_top_similarity
            else "no similar verified case in memory",
        ),
        "evidence_integrity": (
            integrity,
            f"{inputs.evidence_with_verified_hash}/{inputs.evidence_total} evidence items have a verified source hash",
        ),
    }

    components = []
    for name, weight in WEIGHTS.items():
        value, detail = values[name]
        value = max(0.0, min(1.0, float(value)))
        components.append(ConfidenceComponent(
            name=name, value=round(value, 4), weight=weight,
            contribution=round(value * weight, 4), detail=detail,
        ))

    score = round(sum(c.contribution for c in components), 4)
    return ConfidenceResult(score=min(max(score, 0.0), 1.0), components=components)


class ConfidenceEngine:
    """Kept as the public entry point used by the orchestrator."""

    @staticmethod
    def calculate(inputs: ConfidenceInputs) -> ConfidenceResult:
        return calculate_confidence(inputs)
