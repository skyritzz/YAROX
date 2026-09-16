import asyncio
import json
import uuid
from typing import Dict, Any, List
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession

from agents.memory import MemoryAgent
from agents.triage import TriageAgent
from agents.timeline import TimelineAgent
from agents.threat_intel import ThreatIntelAgent
from agents.report import ReportAgent
from models.investigation import InvestigationCase, EvidenceItem, Severity, InvestigationStatus
from security.mitre.knowledge_base import mitre_kb

class AgentEvaluator:
    """
    Unit / Agent-Level Isolated Evaluation.
    Evaluates individual AI agents with structured test inputs to verify deterministic behaviors,
    guardrails, and output format conformance independently from the full end-to-end pipeline.
    """
    def __init__(self):
        self.memory_agent = MemoryAgent()
        self.triage_agent = TriageAgent()
        self.timeline_agent = TimelineAgent()
        self.threat_intel_agent = ThreatIntelAgent()
        self.report_agent = ReportAgent()

    def _create_mock_session(self):
        mock_db = AsyncMock(spec=AsyncSession)
        def mock_add(instance):
            if hasattr(instance, "id") and instance.id is None:
                instance.id = uuid.uuid4()
        mock_db.add = MagicMock(side_effect=mock_add)
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()
        mock_db.execute = AsyncMock(return_value=MagicMock(
            scalar_one_or_none=lambda: None,
            scalars=lambda: MagicMock(all=lambda: [])
        ))
        return mock_db

    async def evaluate_triage_guardrails(self) -> Dict[str, Any]:
        """
        Verifies that TriageAgent enforces deterministic severity floor when LLM suggests LOW on a critical rule.
        """
        case = InvestigationCase(
            id=uuid.uuid4(),
            title="Brute Force",
            description="Matched Rule",
            severity=Severity.CRITICAL,
            status=InvestigationStatus.OPEN
        )
        evidence = [
            EvidenceItem(id=uuid.uuid4(), artifact="admin", evidence_type="AUTHENTICATION_FAILURE", reason="Bad Password", importance_score=0.9)
        ]
        
        mock_db = self._create_mock_session()
        mock_llm_response = '{"severity": "LOW", "summary": "Harmless failed login", "priority_score": 0.1}'
        
        with patch("services.llm_service.llm_service.generate", new_callable=AsyncMock, return_value=mock_llm_response):
            with patch("websocket.investigation_ws.manager.broadcast", new_callable=AsyncMock):
                result = await self.triage_agent.analyze(mock_db, case, evidence)
                
                guardrail_applied = (result.get("severity") in ("MEDIUM", "HIGH", "CRITICAL")) and ("guardrail_applied" in result)
                return {
                    "agent": "TriageAgent",
                    "test": "severity_floor_guardrail",
                    "passed": guardrail_applied,
                    "assigned_severity": result.get("severity"),
                    "guardrail_applied": result.get("guardrail_applied")
                }

    async def evaluate_threat_intel_mitre_validation(self) -> Dict[str, Any]:
        """
        Verifies that ThreatIntelAgent strips hallucinated or invalid MITRE technique IDs.
        """
        case = InvestigationCase(id=uuid.uuid4(), title="Process Attack", severity=Severity.HIGH, status=InvestigationStatus.OPEN)
        from datetime import datetime, timezone
        evidence_id = uuid.uuid4()
        evidence = [EvidenceItem(id=evidence_id, timestamp=datetime.now(timezone.utc), source="Sysmon", artifact="powershell.exe", evidence_type="PROCESS_EXECUTION", reason="Encoded cmd", importance_score=0.8)]
        
        mock_db = self._create_mock_session()

        # LLM returns 1 valid technique (T1059) and 1 completely fake technique (T9999_FAKE), both citing evidence
        mock_llm_response = json.dumps({
            "mitre_mapping": [
                {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution", "evidence_ids": [str(evidence_id)]},
                {"technique_id": "T9999_FAKE", "technique_name": "Fake Technique", "tactic": "Unknown", "evidence_ids": [str(evidence_id)]}
            ],
            "historical_insight": "No prior incidents."
        })

        with patch("services.llm_service.llm_service.generate", new_callable=AsyncMock, return_value=mock_llm_response):
            with patch("memory.service.memory_service.find_similar_cases", new_callable=AsyncMock, return_value=[]):
                with patch("websocket.investigation_ws.manager.broadcast", new_callable=AsyncMock):
                    result = await self.threat_intel_agent.analyze(mock_db, case, evidence)
                    
                    tech_ids = [m["technique_id"] for m in result.get("mitre_mapping", [])]
                    passed = ("T1059" in tech_ids) and ("T9999_FAKE" not in tech_ids)
                    
                    return {
                        "agent": "ThreatIntelAgent",
                        "test": "mitre_kb_validation",
                        "passed": passed,
                        "retained_techniques": tech_ids
                    }

    # Alias for test compatibility
    evaluate_threat_intel_kb_validation = evaluate_threat_intel_mitre_validation

    async def evaluate_timeline_ordering(self) -> Dict[str, Any]:
        """
        Verifies that TimelineAgent handles evidence and outputs valid timeline JSON.
        """
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        case = InvestigationCase(id=uuid.uuid4(), title="Multi-Event Attack", severity=Severity.HIGH, status=InvestigationStatus.OPEN)
        evidence = [
            EvidenceItem(id=uuid.uuid4(), timestamp=now - timedelta(minutes=5), source="Windows Security", artifact="login.exe", evidence_type="AUTH", reason="First event", importance_score=0.5),
            EvidenceItem(id=uuid.uuid4(), timestamp=now, source="Sysmon", artifact="cmd.exe", evidence_type="PROCESS", reason="Second event", importance_score=0.8)
        ]
        
        mock_db = self._create_mock_session()

        mock_llm_response = json.dumps({
            "timeline": [
                {"time": evidence[0].timestamp.isoformat(), "action": "Failed logon", "details": "login.exe", "evidence_ids": [str(evidence[0].id)]},
                {"time": evidence[1].timestamp.isoformat(), "action": "Process execution", "details": "cmd.exe", "evidence_ids": [str(evidence[1].id)]}
            ]
        })

        with patch("services.llm_service.llm_service.generate", new_callable=AsyncMock, return_value=mock_llm_response):
            with patch("websocket.investigation_ws.manager.broadcast", new_callable=AsyncMock):
                result = await self.timeline_agent.analyze(mock_db, case, evidence)
                passed = len(result.get("timeline", [])) == 2
                return {
                    "agent": "TimelineAgent",
                    "test": "timeline_ordering",
                    "passed": passed,
                    "event_count": len(result.get("timeline", []))
                }

    async def evaluate_report_recommendations(self) -> Dict[str, Any]:
        """
        Verifies that ReportAgent produces executive summary and 3 recommendations.
        """
        from datetime import datetime, timezone
        case = InvestigationCase(id=uuid.uuid4(), title="Credential Compromise", severity=Severity.HIGH, status=InvestigationStatus.OPEN)
        evidence_id = uuid.uuid4()
        evidence = [EvidenceItem(id=evidence_id, timestamp=datetime.now(timezone.utc), source="Windows Security", artifact="administrator", evidence_type="AUTHENTICATION_FAILURE", reason="Repeated failed logons", importance_score=0.8)]
        triage_data = {"summary": "Brute force confirmed", "severity": "HIGH", "status": "completed"}
        timeline_data = {"timeline": [], "status": "completed"}
        threat_data = {"mitre_mapping": [{"technique_id": "T1110", "technique_name": "Brute Force", "evidence_ids": [str(evidence_id)]}], "status": "completed"}

        mock_db = self._create_mock_session()

        cited = [str(evidence_id)]
        mock_llm_response = json.dumps({
            "executive_summary": "Credential theft incident confirmed on domain host.",
            "recommendations": [
                {"action": "Reset compromised administrator credentials immediately", "rationale": "Repeated failures", "evidence_ids": cited},
                {"action": "Isolate originating workstation from internal network", "rationale": "Source of attempts", "evidence_ids": cited},
                {"action": "Audit Active Directory logon logs for anomalous lateral access", "rationale": "Scope check", "evidence_ids": cited},
                {"action": "Uncited recommendation that must be rejected", "rationale": "none", "evidence_ids": []}
            ]
        })

        with patch("services.llm_service.llm_service.generate", new_callable=AsyncMock, return_value=mock_llm_response):
            with patch("websocket.investigation_ws.manager.broadcast", new_callable=AsyncMock):
                result = await self.report_agent.analyze(mock_db, case, evidence, triage_data, timeline_data, threat_data)
                recs = result.get("recommendations", [])
                passed = len(recs) == 3 and recs[0]["action"].startswith("Reset") and all(r["evidence_ids"] == cited for r in recs)
                return {
                    "agent": "ReportAgent",
                    "test": "recommendation_structure",
                    "passed": passed,
                    "recommendations_count": len(recs)
                }

agent_evaluator = AgentEvaluator()
