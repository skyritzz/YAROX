from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from datetime import datetime, timezone
from typing import List, Optional
import uuid
from pydantic import BaseModel

from database.session import get_db
from models.investigation import (
    InvestigationCase,
    AgentExecution,
    EvidenceItem,
    InvestigationStatus,
    Severity,
    CaseNote,
    AuditLog
)
from models.user import User
from core.auth import require_authenticated, require_analyst_or_admin
from core.audit import record_audit_log
from schemas.case_management import (
    CaseNoteCreate,
    CaseNoteResponse,
    CaseAssignRequest,
    CaseAssignResponse,
    SeverityOverrideRequest,
    SeverityOverrideResponse,
    CaseReopenRequest,
    CaseReopenResponse,
    AuditLogResponse
)
from agents.orchestrator import orchestrator
from export.report_generator import report_generator
from memory.service import memory_service
from schemas.memory import InvestigationFingerprint
from workers.tasks.memory_tasks import index_resolved_investigation_task
import hashlib

router = APIRouter()

def validate_uuid(id_str: str) -> uuid.UUID:
    try:
        return uuid.UUID(id_str)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID format: {id_str}"
        )

@router.get("/")
async def get_investigations(
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(InvestigationCase)
        .options(
            selectinload(InvestigationCase.evidence_items),
            selectinload(InvestigationCase.assigned_to),
            selectinload(InvestigationCase.resolved_by)
        )
        .order_by(InvestigationCase.created_at.desc())
    )
    return result.scalars().all()

@router.get("/{id}")
async def get_investigation(
    id: str,
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db)
):
    case_uuid = validate_uuid(id)
    result = await db.execute(
        select(InvestigationCase)
        .options(
            selectinload(InvestigationCase.evidence_items),
            selectinload(InvestigationCase.agent_executions).selectinload(AgentExecution.reasoning_steps),
            selectinload(InvestigationCase.agent_executions).selectinload(AgentExecution.tool_calls),
            selectinload(InvestigationCase.mitre_techniques),
            selectinload(InvestigationCase.assigned_to),
            selectinload(InvestigationCase.resolved_by),
            selectinload(InvestigationCase.notes).selectinload(CaseNote.user),
            selectinload(InvestigationCase.audit_logs).selectinload(AuditLog.user)
        )
        .where(InvestigationCase.id == case_uuid)
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return case

@router.get("/{id}/executions")
async def get_investigation_executions(
    id: str,
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db)
):
    case_uuid = validate_uuid(id)
    result = await db.execute(
        select(AgentExecution)
        .where(AgentExecution.investigation_id == case_uuid)
        .order_by(AgentExecution.started_at.desc())
    )
    return result.scalars().all()

@router.get("/{id}/executions/{execution_id}")
async def get_investigation_execution(
    id: str,
    execution_id: str,
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db)
):
    case_uuid = validate_uuid(id)
    exec_uuid = validate_uuid(execution_id)
    result = await db.execute(
        select(AgentExecution)
        .options(
            selectinload(AgentExecution.reasoning_steps),
            selectinload(AgentExecution.tool_calls),
            selectinload(AgentExecution.case).selectinload(InvestigationCase.evidence_items)
        )
        .where(AgentExecution.id == exec_uuid, AgentExecution.investigation_id == case_uuid)
    )
    execution = result.scalar_one_or_none()
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    timeline = []
    for step in execution.reasoning_steps:
        timeline.append({
            "event_id": str(step.id),
            "investigation_id": id,
            "execution_id": execution_id,
            "timestamp": step.timestamp.isoformat() if step.timestamp else None,
            "agent_name": execution.agent_name,
            "step_type": step.step_type,
            "payload": step.content,
            "confidence": execution.confidence if step.step_type == 'decision_made' else None,
            "evidence_ids": [],
            "tool_call_id": None
        })
    timeline.sort(key=lambda x: x["timestamp"] if x["timestamp"] else "")

    decision_step = next((s for s in execution.reasoning_steps if s.step_type == 'decision_made'), None)
    evidence_items = [e for e in execution.case.evidence_items if getattr(e, 'related_agent', None) == execution.agent_name]

    return {
        "execution": {
            "id": str(execution.id),
            "agent_name": execution.agent_name,
            "status": execution.status,
            "confidence": execution.confidence,
            "started_at": execution.started_at.isoformat() if execution.started_at else None,
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
            "confidence_explanation": execution.confidence_explanation
        },
        "summary": {
            "title": f"Execution of {execution.agent_name}"
        },
        "metrics": {
            "total_execution_time_ms": execution.total_execution_time_ms,
            "tool_execution_time_ms": execution.tool_execution_time_ms,
            "llm_execution_time_ms": execution.llm_execution_time_ms,
            "reasoning_step_count": execution.reasoning_step_count,
            "tool_call_count": execution.tool_call_count
        },
        "timeline": timeline,
        "evidence": evidence_items,
        "tool_calls": execution.tool_calls,
        "decision": decision_step.content if decision_step else None
    }

@router.post("/{id}/analyze")
async def analyze_investigation(
    id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_analyst_or_admin),
    db: AsyncSession = Depends(get_db)
):
    case_uuid = validate_uuid(id)
    result = await db.execute(select(InvestigationCase).where(InvestigationCase.id == case_uuid))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    background_tasks.add_task(orchestrator.run_investigation, db, str(case.id))
    return {"message": "Analysis started in background.", "investigation_id": str(case.id)}

# ==============================================================================
# Phase 5.1 Case Management APIs (Notes, Assignment, Severity, Reopen, Audit)
# ==============================================================================

@router.get("/{id}/notes", response_model=List[CaseNoteResponse])
async def get_case_notes(
    id: str,
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieves all notes attached to an investigation case in chronological order.
    """
    case_uuid = validate_uuid(id)
    case_res = await db.execute(select(InvestigationCase).where(InvestigationCase.id == case_uuid))
    if not case_res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Investigation not found")

    result = await db.execute(
        select(CaseNote)
        .options(selectinload(CaseNote.user))
        .where(CaseNote.case_id == case_uuid)
        .order_by(CaseNote.created_at.desc())
    )
    return result.scalars().all()

@router.post("/{id}/notes", response_model=CaseNoteResponse, status_code=status.HTTP_201_CREATED)
async def create_case_note(
    id: str,
    request: CaseNoteCreate,
    current_user: User = Depends(require_analyst_or_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Creates an analyst note attached to an investigation case and records an immutable audit log.
    """
    case_uuid = validate_uuid(id)
    case_res = await db.execute(select(InvestigationCase).where(InvestigationCase.id == case_uuid))
    case = case_res.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")

    note = CaseNote(
        case_id=case_uuid,
        user_id=current_user.id,
        content=request.content
    )
    db.add(note)
    await db.flush()

    # Immutable Audit Log
    await record_audit_log(
        db=db,
        case_id=case_uuid,
        user_id=current_user.id,
        action="NOTE_CREATED",
        details={
            "note_id": str(note.id),
            "content_preview": note.content[:100] + ("..." if len(note.content) > 100 else "")
        }
    )
    case.updated_at = datetime.now(timezone.utc)
    await db.commit()

    # Reload with user relationship
    result = await db.execute(
        select(CaseNote)
        .options(selectinload(CaseNote.user))
        .where(CaseNote.id == note.id)
    )
    return result.scalar_one()

@router.patch("/{id}/assign", response_model=CaseAssignResponse)
async def assign_investigation(
    id: str,
    request: CaseAssignRequest,
    current_user: User = Depends(require_analyst_or_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Assigns or unassigns an investigation case to a user, recording an immutable audit log.
    """
    case_uuid = validate_uuid(id)
    result = await db.execute(select(InvestigationCase).where(InvestigationCase.id == case_uuid))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")

    target_user_email = None
    if request.assigned_to_user_id is not None:
        user_res = await db.execute(select(User).where(User.id == request.assigned_to_user_id))
        target_user = user_res.scalar_one_or_none()
        if not target_user:
            raise HTTPException(status_code=404, detail="Assigned user not found")
        target_user_email = target_user.email

    prev_assignee = str(case.assigned_to_user_id) if case.assigned_to_user_id else None
    new_assignee = str(request.assigned_to_user_id) if request.assigned_to_user_id else None

    case.assigned_to_user_id = request.assigned_to_user_id
    case.updated_at = datetime.now(timezone.utc)

    await record_audit_log(
        db=db,
        case_id=case_uuid,
        user_id=current_user.id,
        action="CASE_ASSIGNED",
        details={
            "previous_assigned_to": prev_assignee,
            "new_assigned_to": new_assignee,
            "assigned_to_email": target_user_email
        }
    )
    await db.commit()

    return CaseAssignResponse(
        id=case.id,
        assigned_to_user_id=case.assigned_to_user_id,
        message="Case assignment updated successfully"
    )

@router.patch("/{id}/severity", response_model=SeverityOverrideResponse)
async def override_investigation_severity(
    id: str,
    request: SeverityOverrideRequest,
    current_user: User = Depends(require_analyst_or_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Manually overrides case severity with a mandatory justification reason, recording an immutable audit log.
    """
    case_uuid = validate_uuid(id)
    result = await db.execute(select(InvestigationCase).where(InvestigationCase.id == case_uuid))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")

    prev_severity = case.severity
    case.severity = request.severity
    case.updated_at = datetime.now(timezone.utc)

    await record_audit_log(
        db=db,
        case_id=case_uuid,
        user_id=current_user.id,
        action="SEVERITY_OVERRIDDEN",
        details={
            "previous_severity": prev_severity.value,
            "new_severity": request.severity.value,
            "reason": request.reason
        }
    )
    await db.commit()

    return SeverityOverrideResponse(
        id=case.id,
        previous_severity=prev_severity.value,
        severity=case.severity.value,
        reason=request.reason
    )

@router.post("/{id}/reopen", response_model=CaseReopenResponse)
async def reopen_investigation(
    id: str,
    request: CaseReopenRequest = CaseReopenRequest(),
    current_user: User = Depends(require_analyst_or_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Reopens a closed investigation case from terminal states (RESOLVED, FALSE_POSITIVE) back to OPEN.
    Clears resolution attribution and records an immutable audit log.
    """
    case_uuid = validate_uuid(id)
    result = await db.execute(select(InvestigationCase).where(InvestigationCase.id == case_uuid))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if case.status not in (InvestigationStatus.RESOLVED, InvestigationStatus.FALSE_POSITIVE):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot reopen case with status '{case.status.value}'. Reopening is only allowed from terminal states (RESOLVED, FALSE_POSITIVE)."
        )

    prev_status = case.status
    case.status = InvestigationStatus.OPEN
    case.resolved_by_user_id = None
    case.resolved_at = None
    case.updated_at = datetime.now(timezone.utc)

    reason_text = request.reason or "Reopened by analyst"
    await record_audit_log(
        db=db,
        case_id=case_uuid,
        user_id=current_user.id,
        action="CASE_REOPENED",
        details={
            "previous_status": prev_status.value,
            "new_status": InvestigationStatus.OPEN.value,
            "reason": reason_text
        }
    )
    await db.commit()

    return CaseReopenResponse(
        id=case.id,
        status=case.status.value,
        message=f"Case reopened from {prev_status.value} to OPEN"
    )

class StatusUpdateRequest(BaseModel):
    status: InvestigationStatus
    reason: Optional[str] = None

@router.patch("/{id}/status")
async def update_investigation_status(
    id: str,
    request: StatusUpdateRequest,
    current_user: User = Depends(require_analyst_or_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Updates investigation case status, recording resolution attribution and triggering memory archival on RESOLVED.
    """
    case_uuid = validate_uuid(id)
    result = await db.execute(select(InvestigationCase).where(InvestigationCase.id == case_uuid))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    prev_status = case.status
    case.status = request.status
    case.updated_at = datetime.now(timezone.utc)

    action_name = "STATUS_UPDATED"
    if case.status == InvestigationStatus.RESOLVED:
        case.resolved_by_user_id = current_user.id
        case.resolved_at = datetime.now(timezone.utc)
        action_name = "CASE_RESOLVED"
    elif case.status == InvestigationStatus.FALSE_POSITIVE:
        case.resolved_by_user_id = current_user.id
        case.resolved_at = datetime.now(timezone.utc)
        action_name = "CASE_MARKED_FALSE_POSITIVE"
    elif case.status == InvestigationStatus.OPEN and prev_status in (InvestigationStatus.RESOLVED, InvestigationStatus.FALSE_POSITIVE):
        case.resolved_by_user_id = None
        case.resolved_at = None
        action_name = "CASE_REOPENED"

    await record_audit_log(
        db=db,
        case_id=case_uuid,
        user_id=current_user.id,
        action=action_name,
        details={
            "previous_status": prev_status.value,
            "new_status": case.status.value,
            "reason": request.reason
        }
    )
    await db.commit()
    
    # Priority 9: Human-Gated Memory Indexing
    # Only index into long-term memory when a verified analyst marks the case as RESOLVED
    if case.status == InvestigationStatus.RESOLVED:
        index_resolved_investigation_task.delay(str(case.id))
        
    return {"message": "Status updated", "status": case.status.value}

@router.get("/{id}/audit", response_model=List[AuditLogResponse])
async def get_case_audit_logs(
    id: str,
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieves the immutable, chronological audit trail of all mutations and actions on an investigation case.
    """
    case_uuid = validate_uuid(id)
    case_res = await db.execute(select(InvestigationCase).where(InvestigationCase.id == case_uuid))
    if not case_res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Investigation not found")

    result = await db.execute(
        select(AuditLog)
        .options(selectinload(AuditLog.user))
        .where(AuditLog.case_id == case_uuid)
        .order_by(AuditLog.timestamp.asc())
    )
    return result.scalars().all()


@router.get("/{id}/export")
async def export_investigation(
    id: str,
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db)
):
    case_uuid = validate_uuid(id)
    result = await db.execute(
        select(InvestigationCase)
        .options(
            selectinload(InvestigationCase.evidence_items),
            selectinload(InvestigationCase.agent_executions).selectinload(AgentExecution.reasoning_steps),
            selectinload(InvestigationCase.agent_executions).selectinload(AgentExecution.tool_calls),
            selectinload(InvestigationCase.mitre_techniques)
        )
        .where(InvestigationCase.id == case_uuid)
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    pdf_bytes = report_generator.generate_pdf(case, case.evidence_items, case.agent_executions, case.mitre_techniques)
    
    return Response(
        content=pdf_bytes, 
        media_type="application/pdf", 
        headers={"Content-Disposition": f"attachment; filename=SOC_Report_{case.id}.pdf"}
    )

@router.get("/graph/entities")
async def get_entity_graph(
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db)
):
    from models.entity import SecurityEntity, SecurityRelationship
    
    entities_result = await db.execute(select(SecurityEntity))
    entities = entities_result.scalars().all()
    
    rels_result = await db.execute(select(SecurityRelationship))
    relationships = rels_result.scalars().all()
    
    nodes = []
    for e in entities:
        nodes.append({
            "id": str(e.id),
            "label": e.name,
            "type": e.type.value
        })
        
    edges = []
    seen_edges = set()
    
    for r in relationships:
        edge_key = f"{r.source_id}-{r.target_id}-{r.action}"
        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            edges.append({
                "id": str(r.id),
                "source": str(r.source_id),
                "target": str(r.target_id),
                "label": r.action,
                "case_id": str(r.case_id) if r.case_id else None
            })
        
    return {"nodes": nodes, "edges": edges}

@router.get("/{id}/similar")
async def get_similar_investigations(
    id: str,
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db)
):
    case_uuid = validate_uuid(id)
    result = await db.execute(
        select(InvestigationCase)
        .options(selectinload(InvestigationCase.mitre_techniques))
        .where(InvestigationCase.id == case_uuid)
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    ev_res = await db.execute(select(EvidenceItem).where(EvidenceItem.case_id == case_uuid))
    evidence = ev_res.scalars().all()
    
    ips, domains, hashes = set(), set(), set()
    for ev in evidence:
        if ev.evidence_type == 'ip': ips.add(ev.artifact)
        elif ev.evidence_type == 'domain': domains.add(ev.artifact)
        elif ev.evidence_type == 'hash': hashes.add(ev.artifact)

    ioc_str = "".join(sorted(list(ips) + list(domains) + list(hashes)))
    mitre_techs = [mt.technique_id for mt in case.mitre_techniques] if case.mitre_techniques else []
    
    fingerprint = InvestigationFingerprint(
        attack_type=None,
        mitre_techniques=mitre_techs,
        campaign=None,
        risk_score=case.confidence_score or 0.0,
        ioc_hash=hashlib.sha256(ioc_str.encode()).hexdigest(),
        timeline_hash=""
    )
    
    current_summary = f"{case.title} {case.description or ''}"
    await memory_service.initialize()
    similar_cases = await memory_service.find_similar_cases(db, fingerprint, current_summary)
    
    # Priority 10: Truthful memory results. Return empty list if no matches found.
    if not similar_cases:
        return []

    return [sim.model_dump(mode="json") for sim in similar_cases]
