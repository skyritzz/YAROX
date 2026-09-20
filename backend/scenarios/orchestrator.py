"""
Scenario orchestration (Phase 14).

Drives a scenarios.schemas.ScenarioDefinition through YAROX's real, existing
pipeline — ingestion HTTP endpoints or the real replay/canonical-contract
publish path, never a parallel one — and compares what actually happened
against the scenario's declared expectations, producing a structured,
reason-carrying pass/fail result.

Design principles (see docs/PHASE_14_SCENARIO_ORCHESTRATION.md for the full
audit and rationale):

* A scenario never "passes" because an event was accepted by an API. Every
  expectation in ``ExpectedOutcome`` is checked against real, persisted
  database state — event durability, evidence rows, case correlation,
  investigation completion, report persistence — polled with bounded
  timeouts (``scenarios.wait.wait_until``), never assumed.
* Isolation between concurrent executions is anchored to real event IDs
  returned by the real ingestion paths (the only guaranteed-correct
  correlation key), not to a marker field a specific connector parser might
  silently drop. A best-effort trace tag is additionally carried through
  wherever each connector's real parser happens to preserve unknown fields
  verbatim (see ``_apply_isolation`` for exactly which field, per connector) —
  useful for a human debugging a stuck run by inspecting the database
  directly, but never load-bearing for correctness.
* Hostname/user values ARE suffixed per execution — necessary so
  ``correlation.engine.CorrelationEngine`` (which matches on those columns)
  cannot correlate two concurrent executions' events into the same case.
  This is not a new risk: every Phase 11-13 live-verification and connector
  test already does exactly this (e.g. ``f"E2E-SURICATA-{uuid.uuid4().hex[:8]}"``).
  ``tests/test_scenario_orchestration.py`` includes an explicit test proving
  the suffix does not change whether a rule matches.
* Cleanup is strictly scoped to the event/case IDs this execution itself
  produced, deletes in dependency order one statement at a time (a single
  multi-statement call silently rolls back everything if a later statement
  fails on a bare foreign key — see git history of Phase 11-13's live
  verification for the incident that established this), and refuses to run
  while any of this execution's investigations have not reached a terminal
  state (never delete out from under a running Celery task).
"""
import asyncio
import copy
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel, Field
from sqlalchemy import select

from core.config import settings
from database.session import AsyncSessionLocal
from models.event import Event
from models.investigation import (
    AgentExecution,
    EvidenceItem,
    InvestigationCase,
    InvestigationReport,
    InvestigationStatus,
)
from scenarios.schemas import ScenarioDefinition, ScenarioEventDef
from scenarios.wait import wait_until

logger = logging.getLogger("yarox.scenarios")

API_KEY_HEADERS = {"X-API-Key": settings.INGESTION_API_KEY, "content-type": "application/json"}

CONNECTOR_ENDPOINTS = {
    "suricata": "/events/ingest/suricata",
    "sysmon": "/events/ingest/sysmon",
    "splunk": "/events/ingest/splunk",
    "generic": "/events/ingest",
}

# Real-time pacing between events is honored but capped, so a scenario whose
# fixture spans hours of wall-clock time doesn't make a test suite hang —
# the same "smart fast-forward" policy replay.engine.ReplayEngine already
# applies to its own inter-event sleeps, for the same reason.
MAX_INTER_EVENT_SLEEP_SECONDS = 2.0


class EventDispatchResult(BaseModel):
    label: str
    connector: str
    accepted: bool
    event_id: Optional[str] = None
    error: Optional[str] = None


class InvestigationOutcome(BaseModel):
    case_id: str
    reached_terminal_state: bool
    final_case_status: Optional[str] = None
    agent_statuses: Dict[str, str] = Field(default_factory=dict)
    report_id: Optional[str] = None


class ScenarioExecutionResult(BaseModel):
    execution_id: str
    scenario_id: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    passed: bool = False
    reasons: List[str] = Field(default_factory=list)  # non-empty iff passed is False
    warnings: List[str] = Field(default_factory=list)
    events: List[EventDispatchResult] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    case_ids: List[str] = Field(default_factory=list)
    evidence_counts: Dict[str, int] = Field(default_factory=dict)  # evidence_type -> count
    investigations: List[InvestigationOutcome] = Field(default_factory=list)
    cleanup_performed: bool = False
    cleanup_skipped_reason: Optional[str] = None


def _apply_isolation(connector: str, payload: Dict[str, Any], execution_id: str, suffix: str) -> Dict[str, Any]:
    """
    Returns a deep copy of ``payload`` with per-execution-unique hostname/user
    values (required for correlation isolation — see module docstring) and a
    best-effort trace tag, using the field each connector's real parser
    actually preserves unmodified for that connector's shape:

    * suricata/sysmon: any top-level key that connector's parser doesn't read
      survives verbatim into Event.raw_log (both parsers store `raw_log =
      raw_data` untouched) — safe to add a marker key there.
    * splunk: the *envelope* (time/host/source/sourcetype/index/event) is
      Pydantic-validated by SplunkHECIngestRequest before it reaches the
      parser, so an unrecognized top-level key would be silently dropped
      before storage — but `event` is Dict[str, Any], so the marker goes
      there instead.
    * generic/replay: `metadata` is a first-class, pass-through field of the
      canonical contract itself (schemas.canonical_event.CanonicalSecurityEvent),
      so the tag becomes a real, directly-queryable Event.metadata_ key.
    """
    payload = copy.deepcopy(payload)
    tag_key = "_yarox_scenario_execution_id"

    if connector == "suricata":
        if payload.get("host"):
            payload["host"] = f"{payload['host']}-{suffix}"
        payload[tag_key] = execution_id
    elif connector == "sysmon":
        if payload.get("Hostname"):
            payload["Hostname"] = f"{payload['Hostname']}-{suffix}"
        elif payload.get("Computer"):
            payload["Computer"] = f"{payload['Computer']}-{suffix}"
        if payload.get("User"):
            payload["User"] = f"{payload['User']}-{suffix}"
        payload[tag_key] = execution_id
    elif connector == "splunk":
        event = payload.setdefault("event", {})
        if event.get("dest"):
            event["dest"] = f"{event['dest']}-{suffix}"
        if event.get("dvc"):
            event["dvc"] = f"{event['dvc']}-{suffix}"
        if event.get("user"):
            event["user"] = f"{event['user']}-{suffix}"
        event[tag_key] = execution_id
    else:  # generic, replay
        if payload.get("hostname"):
            payload["hostname"] = f"{payload['hostname']}-{suffix}"
        if payload.get("user_name"):
            payload["user_name"] = f"{payload['user_name']}-{suffix}"
        if payload.get("user"):  # older/dataset-shaped events (see scenarios.schemas ConnectorName docstring)
            payload["user"] = f"{payload['user']}-{suffix}"
        meta = payload.setdefault("metadata", {})
        meta["scenario_execution_id"] = execution_id

    return payload


class ScenarioOrchestrator:
    """Stateless — every method takes what it needs as arguments, so concurrent
    ``run()`` calls on one instance (or many) never share mutable state."""

    def validate(self, scenario: ScenarioDefinition) -> List[str]:
        """Semantic checks beyond what Pydantic's own field validators already
        enforce (non-empty events, a real connector value — both already
        structural in scenarios.schemas). Returns a list of problems; empty
        means valid."""
        problems: List[str] = []
        if not scenario.events:
            problems.append("scenario has no events")
        for i, ev in enumerate(scenario.events):
            if not isinstance(ev.payload, dict) or not ev.payload:
                problems.append(f"event[{i}] ('{ev.label}') has an empty or non-dict payload")
        return problems

    async def _dispatch_event(self, client: AsyncClient, connector: str, payload: Dict[str, Any]) -> EventDispatchResult:
        try:
            if connector in ("suricata", "sysmon"):
                res = await client.post(CONNECTOR_ENDPOINTS[connector], json={"event": payload}, headers=API_KEY_HEADERS)
            elif connector == "splunk":
                res = await client.post(CONNECTOR_ENDPOINTS["splunk"], json=payload, headers=API_KEY_HEADERS)
            elif connector == "generic":
                res = await client.post(CONNECTOR_ENDPOINTS["generic"], json=payload, headers=API_KEY_HEADERS)
            elif connector == "replay":
                return await self._dispatch_via_replay_path(payload)
            else:
                return EventDispatchResult(label=payload.get("label", ""), connector=connector, accepted=False, error=f"unknown connector '{connector}'")
        except Exception as e:
            return EventDispatchResult(label="", connector=connector, accepted=False, error=f"request failed: {e}")

        if res.status_code not in (200, 202):
            return EventDispatchResult(label="", connector=connector, accepted=False, error=f"HTTP {res.status_code}: {res.text[:500]}")
        body = res.json()
        return EventDispatchResult(label="", connector=connector, accepted=True, event_id=body.get("event_id"))

    async def _dispatch_via_replay_path(self, payload: Dict[str, Any]) -> EventDispatchResult:
        """The real, lower-level path replay.engine.ReplayEngine.stream_events() itself
        uses: GenericJSONParser.parse() (-> CanonicalSecurityEvent.from_raw()) followed
        by a direct publish onto the real event bus. See scenarios.schemas'
        ConnectorName docstring for why this exists separately from "generic"."""
        from core.events import event_bus
        from plugins.parsers.generic import generic_parser
        from schemas.canonical_event import CanonicalEventValidationError

        try:
            parsed = generic_parser.parse(payload)
        except CanonicalEventValidationError as e:
            return EventDispatchResult(label="", connector="replay", accepted=False, error=f"validation failed: {e}")
        event_id = str(parsed["id"])
        await event_bus.publish("EventNormalized", parsed)
        return EventDispatchResult(label="", connector="replay", accepted=True, event_id=event_id)

    async def run(
        self,
        scenario: ScenarioDefinition,
        *,
        wait_for_investigation: bool = True,
        event_storage_timeout: float = 15.0,
        investigation_timeout: float = 180.0,
        cleanup: bool = False,
    ) -> ScenarioExecutionResult:
        execution_id = str(uuid.uuid4())
        suffix = execution_id[:8]
        started_at = datetime.now(timezone.utc)
        result = ScenarioExecutionResult(execution_id=execution_id, scenario_id=scenario.scenario_id, started_at=started_at)

        problems = self.validate(scenario)
        if problems:
            result.reasons.extend(f"invalid scenario definition: {p}" for p in problems)
            result.finished_at = datetime.now(timezone.utc)
            return result

        logger.info("Scenario %s execution %s starting (%d events)", scenario.scenario_id, execution_id, len(scenario.events))

        # 1. Dispatch every event through its real, existing path, honoring relative
        # timing (capped, same policy as ReplayEngine's own pacing).
        from api.main import app
        elapsed = 0.0
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            for ev in scenario.events:
                sleep_for = min(max(ev.relative_offset_seconds - elapsed, 0.0), MAX_INTER_EVENT_SLEEP_SECONDS)
                if sleep_for > 0:
                    await asyncio.sleep(sleep_for)
                elapsed = max(elapsed, ev.relative_offset_seconds)

                tagged_payload = _apply_isolation(ev.connector, ev.payload, execution_id, suffix)
                dispatch = await self._dispatch_event(client, ev.connector, tagged_payload)
                dispatch.label = ev.label
                result.events.append(dispatch)
                if not dispatch.accepted:
                    result.reasons.append(f"event '{ev.label}' was not accepted: {dispatch.error}")
                elif dispatch.event_id:
                    result.event_ids.append(dispatch.event_id)

        if not result.event_ids:
            result.reasons.append("no events were accepted; nothing to verify")
            result.finished_at = datetime.now(timezone.utc)
            return result

        # 2. Confirm durable storage for every accepted event — acceptance alone
        # (a 2xx response) is exactly the false signal this orchestrator exists to
        # not trust; the event must actually land in Postgres via the real bus.
        event_uuids = [uuid.UUID(eid) for eid in result.event_ids]
        stored = await wait_until(lambda: self._all_events_stored(event_uuids), timeout=event_storage_timeout)
        if not stored:
            result.reasons.append(
                f"not all {len(event_uuids)} accepted events were durably stored within {event_storage_timeout}s"
            )

        # 3. Discover cases/evidence correlated to THIS execution's events specifically
        # (joined on the real event IDs returned above — never on the trace tag, which
        # is best-effort only; see module docstring). Detection runs asynchronously off
        # the real event bus (EventStored -> detection_consumer), strictly after storage
        # confirmation above — a single query immediately after storage would race it.
        # For a scenario expecting a detection, poll until enough evidence appears (or
        # detection_timeout elapses, recorded as a reason, never silently treated as
        # "nothing happened"); a scenario expecting NO detection has nothing to poll
        # for, so it gets a fixed grace window instead — long enough for detection to
        # have fired if it were going to, short enough not to pad every negative-control
        # run by a full timeout.
        expected_min_evidence = max(scenario.expected.min_evidence_count, 1) if scenario.expected.should_create_case else 0

        async def _enough_evidence() -> bool:
            _, rows = await self._discover_cases_and_evidence(event_uuids)
            return len(rows) >= expected_min_evidence

        if expected_min_evidence > 0:
            settled = await wait_until(_enough_evidence, timeout=event_storage_timeout)
            if not settled:
                result.warnings.append(f"expected evidence did not fully appear within {event_storage_timeout}s of storage")
        else:
            await asyncio.sleep(min(event_storage_timeout, 5.0))

        case_ids, evidence_rows = await self._discover_cases_and_evidence(event_uuids)
        result.case_ids = [str(c) for c in case_ids]
        for row_evidence_type in evidence_rows:
            result.evidence_counts[row_evidence_type] = result.evidence_counts.get(row_evidence_type, 0) + 1

        # 4. Wait for each discovered case's investigation to reach a terminal state,
        # if the scenario expects one to run.
        if wait_for_investigation and scenario.expected.expect_investigation_to_run and case_ids:
            for case_id in case_ids:
                outcome = await self._wait_for_investigation(case_id, investigation_timeout)
                result.investigations.append(outcome)
                if not outcome.reached_terminal_state:
                    result.warnings.append(
                        f"investigation for case {case_id} did not reach a terminal state within {investigation_timeout}s"
                    )

        # 5. Compare actual vs. expected.
        result.reasons.extend(await self._evaluate_expectations(scenario, result, case_ids))
        result.passed = len(result.reasons) == 0
        result.finished_at = datetime.now(timezone.utc)

        logger.info(
            "Scenario %s execution %s finished: %s (%d reasons, %d warnings)",
            scenario.scenario_id, execution_id, "PASSED" if result.passed else "FAILED",
            len(result.reasons), len(result.warnings),
        )

        # 6. Cleanup, only if explicitly requested and only this execution's own data,
        # and only once every investigation it triggered is confirmed terminal.
        if cleanup:
            await self._cleanup(result)

        return result

    async def _all_events_stored(self, event_ids: List[uuid.UUID]) -> bool:
        async with AsyncSessionLocal() as session:
            for eid in event_ids:
                if (await session.get(Event, eid)) is None:
                    return False
            return True

    async def _discover_cases_and_evidence(self, event_ids: List[uuid.UUID]) -> Tuple[List[uuid.UUID], List[str]]:
        async with AsyncSessionLocal() as session:
            rows = (
                await session.execute(select(EvidenceItem).where(EvidenceItem.event_id.in_(event_ids)))
            ).scalars().all()
            case_ids = sorted({r.case_id for r in rows}, key=str)
            evidence_types = [r.evidence_type for r in rows]
            return case_ids, evidence_types

    async def _wait_for_investigation(self, case_id: uuid.UUID, timeout: float) -> InvestigationOutcome:
        """Two stages against one overall deadline: first wait for the Celery-dispatched
        investigation to actually start (at least one AgentExecution row exists for this
        case — dispatch itself is async, so this can lag event storage by a moment),
        then wait for the case's own status to leave ANALYZING.

        Deliberately NOT based on AgentExecution rows all being non-"running": between
        one agent finishing and the next one's row being created (agents/orchestrator.py
        runs Memory -> {Triage, Timeline, Threat Intel} concurrently -> Report, each a
        separate start_execution() call), there is a real window where every EXISTING
        row is terminal but the run is not actually done — a genuine race found while
        building this method (a live run's SOC Lead step was skipped entirely because
        "no rows running" was briefly true right before SOC Lead's own row existed).
        core/case_state.py's InvestigationCase.status is set exactly once, atomically,
        at the true end of orchestrator.AgentOrchestrator._run_locked() (WAITING_FOR_REVIEW
        on success, back to OPEN/previous on failure) — immune to that race."""
        deadline = time.monotonic() + timeout

        async def _entered_analyzing() -> bool:
            async with AsyncSessionLocal() as session:
                case = await session.get(InvestigationCase, case_id)
                return case is not None and case.status != InvestigationStatus.OPEN

        started = await wait_until(_entered_analyzing, timeout=max(deadline - time.monotonic(), 0.1))

        finished = False
        if started:
            async def _left_analyzing() -> bool:
                async with AsyncSessionLocal() as session:
                    case = await session.get(InvestigationCase, case_id)
                    return case is not None and case.status != InvestigationStatus.ANALYZING

            finished = await wait_until(_left_analyzing, timeout=max(deadline - time.monotonic(), 0.1))

        async with AsyncSessionLocal() as session:
            case = await session.get(InvestigationCase, case_id)
            agent_rows = (await session.execute(select(AgentExecution).where(AgentExecution.investigation_id == case_id))).scalars().all()
            report = (
                await session.execute(
                    select(InvestigationReport).where(InvestigationReport.case_id == case_id, InvestigationReport.is_current.is_(True))
                )
            ).scalars().first()
            return InvestigationOutcome(
                case_id=str(case_id),
                reached_terminal_state=finished,
                final_case_status=case.status.value if case else None,
                agent_statuses={r.agent_name: r.status for r in agent_rows},
                report_id=str(report.id) if report else None,
            )

    async def _evaluate_expectations(self, scenario: ScenarioDefinition, result: ScenarioExecutionResult, case_ids: List[uuid.UUID]) -> List[str]:
        reasons: List[str] = []
        exp = scenario.expected
        actual_case_count = len(case_ids)

        if exp.should_create_case and actual_case_count == 0:
            reasons.append("expected at least one case to be created, but none were")
        if not exp.should_create_case and actual_case_count > 0:
            reasons.append(f"expected no case to be created, but {actual_case_count} were: {result.case_ids}")
        if actual_case_count < exp.min_case_count:
            reasons.append(f"expected at least {exp.min_case_count} case(s), got {actual_case_count}")
        if exp.max_case_count is not None and actual_case_count > exp.max_case_count:
            reasons.append(f"expected at most {exp.max_case_count} case(s), got {actual_case_count}")
        if exp.expect_correlated_single_case and actual_case_count > 1:
            reasons.append(f"expected all detections to correlate into one case, got {actual_case_count} distinct cases: {result.case_ids}")

        for expected_det in exp.expected_detections:
            if expected_det.evidence_type is None:
                actual = sum(result.evidence_counts.values())
            else:
                actual = result.evidence_counts.get(expected_det.evidence_type, 0)
            if actual < expected_det.min_count:
                reasons.append(
                    f"expected >= {expected_det.min_count} evidence of type "
                    f"'{expected_det.evidence_type or 'any'}', got {actual}"
                )

        total_evidence = sum(result.evidence_counts.values())
        if total_evidence < exp.min_evidence_count:
            reasons.append(f"expected >= {exp.min_evidence_count} total evidence rows, got {total_evidence}")

        if exp.expect_investigation_to_run:
            if not result.investigations:
                reasons.append("expected an investigation to run, but none were observed (no case to investigate, or wait was disabled)")
            for inv in result.investigations:
                if not inv.reached_terminal_state:
                    reasons.append(f"investigation for case {inv.case_id} did not reach a terminal state — cannot confirm pass or fail")
                elif exp.expect_report and not inv.report_id:
                    reasons.append(f"investigation for case {inv.case_id} finished but no persisted report was found")

        return reasons

    async def _cleanup(self, result: ScenarioExecutionResult) -> None:
        if result.investigations and any(not inv.reached_terminal_state for inv in result.investigations):
            result.cleanup_skipped_reason = "at least one investigation had not reached a terminal state; refusing to delete data out from under a running Celery task"
            logger.warning("Skipping cleanup for execution %s: %s", result.execution_id, result.cleanup_skipped_reason)
            return

        async def exec_stmt(stmt):
            async with AsyncSessionLocal() as session:
                await session.execute(stmt)
                await session.commit()

        from sqlalchemy import delete

        case_uuids = [uuid.UUID(c) for c in result.case_ids]
        event_uuids = [uuid.UUID(e) for e in result.event_ids]

        if case_uuids:
            exec_ids_stmt = select(AgentExecution.id).where(AgentExecution.investigation_id.in_(case_uuids))
            async with AsyncSessionLocal() as session:
                exec_ids = [r for (r,) in (await session.execute(exec_ids_stmt)).all()]

            from models.investigation import AgentFinding, AgentFindingEvidence, AgentReasoningStep, AgentToolCall
            from models.mitre import AttackTechnique as AttackTechniqueModel
            from models.entity import SecurityRelationship

            if exec_ids:
                await exec_stmt(delete(AgentReasoningStep).where(AgentReasoningStep.execution_id.in_(exec_ids)))
                await exec_stmt(delete(AgentToolCall).where(AgentToolCall.execution_id.in_(exec_ids)))
                finding_ids_stmt = select(AgentFinding.id).where(AgentFinding.execution_id.in_(exec_ids))
                async with AsyncSessionLocal() as session:
                    finding_ids = [r for (r,) in (await session.execute(finding_ids_stmt)).all()]
                if finding_ids:
                    await exec_stmt(delete(AgentFindingEvidence).where(AgentFindingEvidence.finding_id.in_(finding_ids)))
                await exec_stmt(delete(AgentFinding).where(AgentFinding.execution_id.in_(exec_ids)))
            from models.investigation import AuditLog, CaseNote

            await exec_stmt(delete(InvestigationReport).where(InvestigationReport.case_id.in_(case_uuids)))
            await exec_stmt(delete(AgentExecution).where(AgentExecution.investigation_id.in_(case_uuids)))
            await exec_stmt(delete(EvidenceItem).where(EvidenceItem.case_id.in_(case_uuids)))
            await exec_stmt(delete(AttackTechniqueModel).where(AttackTechniqueModel.case_id.in_(case_uuids)))
            await exec_stmt(delete(SecurityRelationship).where(SecurityRelationship.case_id.in_(case_uuids)))
            await exec_stmt(delete(CaseNote).where(CaseNote.case_id.in_(case_uuids)))
            await exec_stmt(delete(AuditLog).where(AuditLog.case_id.in_(case_uuids)))
            await exec_stmt(delete(InvestigationCase).where(InvestigationCase.id.in_(case_uuids)))

        if event_uuids:
            await exec_stmt(delete(Event).where(Event.id.in_(event_uuids)))

        result.cleanup_performed = True
        logger.info("Cleaned up execution %s: %d case(s), %d event(s)", result.execution_id, len(case_uuids), len(event_uuids))


scenario_orchestrator = ScenarioOrchestrator()
