from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models.event import Event
from models.investigation import InvestigationCase, EvidenceItem, InvestigationStatus
from models.mitre import AttackTechnique
from detection.rules import (
    BaseDetectionRule,
    FailedLoginBruteForce,
    PrivilegeEscalation,
    SuspiciousProcessExecution,
    LateralMovement
)

class DetectionEngine:
    def __init__(self):
        self.rules: List[BaseDetectionRule] = [
            FailedLoginBruteForce(),
            PrivilegeEscalation(),
            SuspiciousProcessExecution(),
            LateralMovement()
        ]

    async def process_event(self, db: AsyncSession, event: Event) -> InvestigationCase | None:
        for rule in self.rules:
            if rule.match(event):
                explanation = rule.explain(event)
                
                from correlation.engine import correlation_engine
                from datetime import datetime, timezone
                
                # Check for Correlation
                case = await correlation_engine.find_related_case(db, event, explanation['mitre_technique_name'])
                
                if not case:
                    # Create New Case
                    case = InvestigationCase(
                        title=f"Automated Detection: {explanation['mitre_technique_name']}",
                        description=explanation['description'],
                        status=InvestigationStatus.OPEN,
                        severity=explanation['severity']
                    )
                    db.add(case)
                    await db.flush() # flush to get case.id
                else:
                    # Update Existing Case
                    case.updated_at = datetime.now(timezone.utc)
                    db.add(case)
                
                # Evaluate Sigma Rules
                from rules.sigma.engine import sigma_engine
                matches = sigma_engine.evaluate(event.raw_log.get('metadata', {}))
                
                sigma_reason = ""
                sigma_risk = 0.8
                if matches:
                    sigma_reason = f"\n\nMatched Sigma Rule: {', '.join([r.title for r in matches])}"
                    sigma_risk = 0.92
                
                # Check if identical evidence already exists in this case
                artifact_val = event.raw_log.get('metadata', {}).get('command_line') or event.user_name or event.hostname
                ev_type = explanation['evidence_type']
                
                existing_ev = await db.execute(
                    select(EvidenceItem).where(
                        EvidenceItem.case_id == case.id,
                        EvidenceItem.artifact == artifact_val,
                        EvidenceItem.evidence_type == ev_type
                    )
                )
                if not existing_ev.scalars().first():
                    evidence = EvidenceItem(
                        case_id=case.id,
                        event_id=event.id,
                        evidence_type=ev_type,
                        source=event.source,
                        timestamp=event.timestamp,
                        artifact=artifact_val,
                        reason=explanation['description'] + sigma_reason,
                        importance_score=sigma_risk
                    )
                    db.add(evidence)
                
                # Create MITRE Technique if it doesn't already exist for this case
                tech_id = explanation['mitre_technique_id']
                existing_tech = await db.execute(
                    select(AttackTechnique).where(
                        AttackTechnique.case_id == case.id,
                        AttackTechnique.technique_id == tech_id
                    )
                )
                if not existing_tech.scalars().first():
                    mitre = AttackTechnique(
                        case_id=case.id,
                        technique_id=tech_id,
                        technique_name=explanation['mitre_technique_name'],
                        tactic=explanation['mitre_tactic'],
                        confidence=0.8,
                        reason=explanation['description']
                    )
                    db.add(mitre)
                
                await db.commit()
                
                # Extract Graph Entities
                await self._extract_entities(db, event, case.id)
                await db.commit()
                
                return case
        return None

    async def _extract_entities(self, db: AsyncSession, event: Event, case_id):
        from models.entity import SecurityEntity, SecurityRelationship, EntityType
        from sqlalchemy.future import select
        
        async def get_or_create(etype, name):
            if not name: return None
            # Truncate large names like long powershell commands to 100 chars
            name = name[:100]
            result = await db.execute(select(SecurityEntity).where(SecurityEntity.name == name, SecurityEntity.type == etype))
            entity = result.scalar_one_or_none()
            if not entity:
                entity = SecurityEntity(type=etype, name=name)
                db.add(entity)
                await db.flush()
            return entity
            
        user = await get_or_create(EntityType.USER, event.user_name)
        host = await get_or_create(EntityType.HOST, event.hostname)
        
        process_name = event.raw_log.get('metadata', {}).get('process_name')
        process = await get_or_create(EntityType.PROCESS, process_name)
        
        # IP addresses from metadata
        ip = await get_or_create(EntityType.IP, event.raw_log.get('metadata', {}).get('ip_address'))
        
        if user and host:
            db.add(SecurityRelationship(source_id=user.id, target_id=host.id, action="logged into", case_id=case_id))
        
        if host and process:
            db.add(SecurityRelationship(source_id=host.id, target_id=process.id, action="executed", case_id=case_id))
            
        if user and ip:
            db.add(SecurityRelationship(source_id=ip.id, target_id=user.id, action="authenticated as", case_id=case_id))

detection_engine = DetectionEngine()
