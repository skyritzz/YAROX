import asyncio
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
        evidence = [EvidenceItem(id=uuid.uuid4(), artifact="powershell.exe", evidence_type="PROCESS_EXECUTION", reason="Encoded cmd", importance_score=0.8)]
        
        mock_db = self._create_mock_session()

        # LLM returns 1 valid technique (T1059) and 1 completely fake technique (T9999_FAKE)
        mock_llm_response = '''{
            "mitre_mapping": [
                {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution"},
                {"technique_id": "T9999_FAKE", "technique_name": "Fake Technique", "tactic": "Unknown"}
            ],
            "historical_insight": "No prior incidents."
        }'''

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
            EvidenceItem(id=uuid.uuid4(), timestamp=now - timedelta(minutes=5), artifact="login.exe", evidence_type="AUTH", reason="First event", importance_score=0.5),
            EvidenceItem(id=uuid.uuid4(), timestamp=now, artifact="cmd.exe", evidence_type="PROCESS", reason="Second event", importance_score=0.8)
        ]
        
        mock_db = self._create_mock_session()

        mock_llm_response = '''{
            "timeline": [
                {"time": "2026-08-22T10:00:00Z", "action": "Failed logon", "details": "login.exe"},
                {"time": "2026-08-22T10:05:00Z", "action": "Process execution", "details": "cmd.exe"}
            ]
        }'''

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
        case = InvestigationCase(id=uuid.uuid4(), title="Credential Compromise", severity=Severity.HIGH, status=InvestigationStatus.OPEN)
        evidence = []
        triage_data = {"summary": "Brute force confirmed", "severity": "HIGH"}
        timeline_data = {"timeline": []}
        threat_data = {"mitre_mapping": [{"technique_name": "Brute Force"}]}

        mock_db = self._create_mock_session()

        mock_llm_response = '''{
            "executive_summary": "Credential theft incident confirmed on domain host.",
            "recommendations": [
                "Reset compromised administrator credentials immediately",
                "Isolate originating workstation from internal network",
                "Audit Active Directory logon logs for anomalous lateral access"
            ]
        }'''

        with patch("services.llm_service.llm_service.generate", new_callable=AsyncMock, return_value=mock_llm_response):
            with patch("websocket.investigation_ws.manager.broadcast", new_callable=AsyncMock):
                result = await self.report_agent.analyze(mock_db, case, evidence, triage_data, timeline_data, threat_data)
                recs = result.get("recommendations", [])
                passed = len(recs) == 3 and "Reset" in recs[0]
                return {
                    "agent": "ReportAgent",
                    "test": "recommendation_structure",
                    "passed": passed,
                    "recommendations_count": len(recs)
                }

agent_evaluator = AgentEvaluator()
