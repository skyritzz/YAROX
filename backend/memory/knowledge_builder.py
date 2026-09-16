import json
import uuid
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from models.investigation import InvestigationCase, EvidenceItem, AgentExecution, AgentReasoningStep
from schemas.memory import InvestigationKnowledgeObject, InvestigationFingerprint, TimelineEvent
from services.llm_service import llm_service
from core.utils import sanitize_evidence, build_sandboxed_agent_prompt
import hashlib

def _compute_timeline_hash(events: list) -> str:
    serialized_events = []
    for ev in events:
        if isinstance(ev, str):
            serialized_events.append(ev.strip())
        elif isinstance(ev, dict):
            serialized_events.append(json.dumps(ev, sort_keys=True))
        elif hasattr(ev, "model_dump"):
            serialized_events.append(json.dumps(ev.model_dump(mode="json"), sort_keys=True))
        else:
            serialized_events.append(str(ev).strip())
    timeline_str = "".join(sorted(serialized_events))
    return hashlib.sha256(timeline_str.encode()).hexdigest()

class KnowledgeBuilder:
    def __init__(self):
        pass

    async def build(self, db: AsyncSession, case_id: str | uuid.UUID) -> tuple[InvestigationKnowledgeObject, InvestigationFingerprint]:
        case_uuid = uuid.UUID(str(case_id)) if isinstance(case_id, str) else case_id

        # 1. Fetch case with all required relationships explicitly loaded to prevent MissingGreenlet
        case_res = await db.execute(
            select(InvestigationCase)
            .options(
                selectinload(InvestigationCase.mitre_techniques),
                selectinload(InvestigationCase.evidence_items),
                selectinload(InvestigationCase.agent_executions).selectinload(AgentExecution.reasoning_steps),
            )
            .where(InvestigationCase.id == case_uuid)
        )
        case = case_res.scalar_one_or_none()
        if not case:
            raise ValueError(f"Investigation {case_id} not found")

        evidence = list(case.evidence_items or [])
        executions = list(case.agent_executions or [])
        
        # Collect reasoning steps without triggering separate queries
        all_steps = []
        for ex in executions:
            for s in (ex.reasoning_steps or []):
                if s.step_type in ['reasoning_complete', 'decision_made']:
                    all_steps.append(s.content)

        # 2. Extract IOCs and structured info
        ips, domains, urls, hashes, users, hosts = set(), set(), set(), set(), set(), set()
        for ev in evidence:
            if ev.evidence_type == 'ip': ips.add(ev.artifact)
            elif ev.evidence_type == 'domain': domains.add(ev.artifact)
            elif ev.evidence_type == 'url': urls.add(ev.artifact)
            elif ev.evidence_type == 'hash': hashes.add(ev.artifact)
            elif ev.evidence_type == 'user': users.add(ev.artifact)
            elif ev.evidence_type == 'host': hosts.add(ev.artifact)

        mitre_techs = [mt.technique_id for mt in (case.mitre_techniques or [])]

        # 3. Use LLM to structure remaining fields with prompt sandboxing
        raw_context = {
            "title": case.title,
            "description": case.description,
            "severity": case.severity.value if hasattr(case.severity, "value") else str(case.severity),
            "evidence": [ev.artifact for ev in evidence],
            "agent_findings": all_steps
        }

        evidence_block = sanitize_evidence(raw_context)

        sev_str = case.severity.value if hasattr(case.severity, "value") else str(case.severity)
        role_desc = "You are an expert SOC analyst structuring verified historical investigation data for long-term memory."
        task_desc = f"Case Title: {case.title}\nSeverity: {sev_str}\nExtract structured knowledge for long-term incident memory."
        format_desc = """Return a JSON object with:
{
    "summary": "High level summary",
    "executive_summary": "One paragraph executive summary",
    "attack_type": "The type of attack (e.g. Credential Theft, Ransomware, etc) or None",
    "malware_family": "Identified malware family or None",
    "campaign": "Identified campaign or None",
    "kill_chain": ["list of kill chain phases"],
    "important_events": [
        {"time": "ISO-8601 timestamp", "action": "What happened", "details": "Supporting detail"},
        "or a plain text description of an event"
    ],
    "attack_story": "A short narrative of the attack",
    "immediate_actions": ["list of immediate actions"],
    "long_term_actions": ["list of long term actions"],
    "lessons_learned": "What can be learned from this"
}
Each item in "important_events" must be either a string OR an object with at least one of: "time", "action", "details", "description", "event", "timestamp".
Return ONLY valid JSON."""

        full_prompt = build_sandboxed_agent_prompt(
            role_instruction=role_desc,
            task_instruction=task_desc,
            evidence_block=evidence_block,
            output_format_instruction=format_desc
        )

        try:
            response_text = await llm_service.generate(full_prompt, "", json_format=True)
            llm_data = json.loads(response_text)
            if not isinstance(llm_data, dict):
                raise ValueError("LLM response is not a valid JSON dictionary")
        except Exception as e:
            print(f"Error generating knowledge with LLM: {e}")
            llm_data = {
                "summary": case.title,
                "executive_summary": "Verified incident recorded in long-term memory.",
                "attack_type": None,
                "malware_family": None,
                "campaign": None,
                "kill_chain": [],
                "important_events": [],
                "attack_story": None,
                "immediate_actions": [],
                "long_term_actions": [],
                "lessons_learned": None
            }

        # Validate and normalize important_events with strict rejection of malformed data.
        # Supported types: str, dict with at least one recognized TimelineEvent field, or TimelineEvent.
        # Unsupported types (int, float, bool, None, list) raise ValueError.
        # Dicts that produce an all-None TimelineEvent (no recognized fields) raise ValueError.
        raw_events = llm_data.get("important_events", [])
        important_events = []
        if isinstance(raw_events, list):
            for idx, ev in enumerate(raw_events):
                if isinstance(ev, str):
                    important_events.append(ev)
                elif isinstance(ev, dict):
                    te = TimelineEvent(**ev)
                    if te.is_empty():
                        raise ValueError(
                            f"LLM returned malformed timeline event at index {idx}: "
                            f"dict {ev!r} has no recognized TimelineEvent fields "
                            f"(time, action, details, description, event, timestamp)."
                        )
                    important_events.append(te)
                elif isinstance(ev, TimelineEvent):
                    important_events.append(ev)
                else:
                    raise ValueError(
                        f"LLM returned unsupported timeline event type at index {idx}: "
                        f"{type(ev).__name__!r} ({ev!r}). "
                        f"Each event must be a string or a dict."
                    )

        # 4. Construct Knowledge Object
        knowledge_obj = InvestigationKnowledgeObject(
            investigation={
                "title": case.title,
                "summary": llm_data.get("summary", case.title),
                "executive_summary": llm_data.get("executive_summary", ""),
                "severity": sev_str,
                "risk_score": case.confidence_score or 0.0
            },
            attack={
                "attack_type": llm_data.get("attack_type"),
                "malware_family": llm_data.get("malware_family"),
                "campaign": llm_data.get("campaign"),
                "mitre_techniques": mitre_techs,
                "kill_chain": llm_data.get("kill_chain", [])
            },
            evidence={
                "ips": list(ips),
                "domains": list(domains),
                "urls": list(urls),
                "hashes": list(hashes),
                "filenames": [],
                "users": list(users),
                "hosts": list(hosts),
                "processes": [],
                "registry_keys": [],
                "commands": []
            },
            timeline={
                "important_events": important_events,
                "attack_story": llm_data.get("attack_story")
            },
            recommendations={
                "immediate_actions": llm_data.get("immediate_actions", []),
                "long_term_actions": llm_data.get("long_term_actions", [])
            },
            lessons_learned=llm_data.get("lessons_learned"),
            metadata={
                "investigation_id": str(case.id),
                "created_at": case.created_at,
                "qdrant_id": "", # To be filled by service
                "knowledge_version": 1,
                "generated_at": datetime.now(timezone.utc)
            }
        )

        # 5. Generate Fingerprint
        ioc_str = "".join(sorted(list(ips) + list(domains) + list(hashes)))
        timeline_hash = _compute_timeline_hash(important_events)
        
        fingerprint = InvestigationFingerprint(
            attack_type=llm_data.get("attack_type"),
            mitre_techniques=mitre_techs,
            campaign=llm_data.get("campaign"),
            risk_score=case.confidence_score or 0.0,
            ioc_hash=hashlib.sha256(ioc_str.encode()).hexdigest(),
            timeline_hash=timeline_hash
        )

        return knowledge_obj, fingerprint

knowledge_builder = KnowledgeBuilder()

