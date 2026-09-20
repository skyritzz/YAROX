"""
Scenario contract (Phase 14).

A ``ScenarioDefinition`` describes a realistic event sequence and what YAROX
is expected to do with it. Expected outcomes (``ScenarioDefinition.expected``)
are kept strictly separate from actual runtime results
(``scenarios.orchestrator.ScenarioExecutionResult``) — a scenario "passing"
is always a comparison between the two, never a proxy signal like "the API
returned 2xx" or "an event was accepted." See ``scenarios.orchestrator`` for
the comparison logic.

Versioned (``ScenarioDefinition.version``) so a future breaking change to the
contract's own shape (a new required field, a changed meaning) can be
distinguished from an additive one, the same policy
``schemas.canonical_event.CANONICAL_EVENT_SCHEMA_VERSION`` already
establishes for the canonical event contract.
"""
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

SCENARIO_CONTRACT_VERSION = "1.0"

# The dispatch mechanisms a scenario event can go through — each maps to a real,
# already-existing path (see scenarios.orchestrator.CONNECTOR_ENDPOINTS):
#   "suricata"/"sysmon"/"splunk" -> the real POST /events/ingest/<name> HTTP endpoints
#     (real auth, real rate limiting, real connector parser — Phase 11).
#   "generic" -> the real POST /events/ingest HTTP endpoint. Requires the payload to
#     already satisfy schemas.ingest.IngestEventRequest (source, event_type, raw_log
#     all present) — the stricter of the two generic paths.
#   "replay" -> the real, lower-level canonical-contract path plugins.parsers.generic.
#     GenericJSONParser.parse() + a direct event bus publish — the exact mechanism
#     replay.engine.ReplayEngine.stream_events() itself uses internally, without HTTP's
#     extra validation layer. Needed for fixtures (e.g. datasets/insider_threat) whose
#     raw event shape predates schemas.ingest.IngestEventRequest and has no raw_log key
#     of its own — CanonicalSecurityEvent.from_raw() tolerates that (raw_log defaults to
#     the whole input dict), IngestEventRequest's stricter schema does not. Using this
#     path rather than inventing a synthetic raw_log wrapper keeps the fixture verbatim.
ConnectorName = Literal["suricata", "sysmon", "splunk", "generic", "replay"]


class ScenarioEventDef(BaseModel):
    """One event in a scenario's sequence."""

    connector: ConnectorName
    relative_offset_seconds: float = Field(
        0.0, ge=0.0,
        description="When to dispatch this event, relative to the start of the scenario run. "
                    "Real time is honored (capped — see orchestrator) so ordering/timing tests are meaningful.",
    )
    payload: Dict[str, Any] = Field(
        ..., description="Raw, connector-shaped payload: real Suricata EVE JSON / Sysmon flattened "
                          "JSON / Splunk HEC envelope / a generic canonical-ish dict, exactly as that "
                          "connector's real ingestion endpoint expects it."
    )
    label: str = Field(..., min_length=1, description="Short human-readable name for this event, for tracing/log output.")


class ExpectedDetection(BaseModel):
    """One detection this scenario expects to see (or, via min_count=0, expects NOT to see)."""

    evidence_type: Optional[str] = Field(
        None, description="EvidenceItem.evidence_type this detection should produce, e.g. "
                           "'NETWORK_INTRUSION_ALERT'. None means 'any detection at all'."
    )
    min_count: int = Field(1, ge=0, description="Minimum number of matching evidence rows expected.")


class ExpectedOutcome(BaseModel):
    """
    What the scenario asserts should be true after running — never what actually happened.
    A negative-control scenario sets should_create_case=False, min_case_count=0,
    max_case_count=0, expected_detections=[] — an explicit, structural way to assert
    "nothing should be detected here," not merely the absence of a positive assertion.
    """

    should_create_case: bool
    min_case_count: int = Field(0, ge=0)
    max_case_count: Optional[int] = Field(None, ge=0)
    expected_detections: List[ExpectedDetection] = Field(default_factory=list)
    expect_correlated_single_case: bool = Field(
        False, description="If true, every detection this scenario produces must land in exactly one case "
                            "(correlation_engine finding/reusing the same case), not multiple separate ones."
    )
    min_evidence_count: int = Field(0, ge=0)
    expect_investigation_to_run: bool = Field(
        False, description="If true, the orchestrator waits for the real Celery-dispatched investigation "
                            "(detection_consumer -> services.investigation_runner.dispatch_investigation) "
                            "to reach a terminal state (InvestigationCase.status leaves ANALYZING)."
    )
    expect_report: bool = Field(False, description="If true, a persisted InvestigationReport row is required.")

    @field_validator("max_case_count")
    @classmethod
    def _max_not_below_min(cls, v: Optional[int], info) -> Optional[int]:
        min_v = info.data.get("min_case_count", 0)
        if v is not None and v < min_v:
            raise ValueError(f"max_case_count ({v}) cannot be less than min_case_count ({min_v})")
        return v


class ScenarioDefinition(BaseModel):
    scenario_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    version: str = SCENARIO_CONTRACT_VERSION
    events: List[ScenarioEventDef] = Field(..., min_length=1)
    expected: ExpectedOutcome
    notes: Optional[str] = Field(
        None, description="Free-text caveats about what this scenario does and does not demonstrate "
                           "(e.g. 'suspicious pattern, not proof of malicious intent') — surfaced in "
                           "reports so a scenario's own framing travels with its result."
    )
