from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from database.session import get_db
from models.investigation import InvestigationCase
from agents.orchestrator import orchestrator
from export.report_generator import report_generator

router = APIRouter()

@router.get("/")
async def get_investigations(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(InvestigationCase)
        .options(selectinload(InvestigationCase.evidence_items))
        .order_by(InvestigationCase.created_at.desc())
    )
    return result.scalars().all()

@router.get("/{id}")
async def get_investigation(id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(InvestigationCase)
        .options(
            selectinload(InvestigationCase.evidence_items),
            selectinload(InvestigationCase.agent_actions),
            selectinload(InvestigationCase.mitre_techniques)
        )
        .where(InvestigationCase.id == id)
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return case

@router.post("/{id}/analyze")
async def analyze_investigation(id: str, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    background_tasks.add_task(orchestrator.run_investigation, db, id)
    return {"message": "Analysis started in background."}

from pydantic import BaseModel

class StatusUpdateRequest(BaseModel):
    status: str

@router.patch("/{id}/status")
async def update_investigation_status(id: str, request: StatusUpdateRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(InvestigationCase).where(InvestigationCase.id == id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    case.status = request.status
    await db.commit()
    return {"message": "Status updated", "status": case.status}

@router.get("/{id}/export")
async def export_investigation(id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(InvestigationCase)
        .options(
            selectinload(InvestigationCase.evidence_items),
            selectinload(InvestigationCase.agent_actions),
            selectinload(InvestigationCase.mitre_techniques)
        )
        .where(InvestigationCase.id == id)
    )
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Investigation not found")
        
    pdf_bytes = report_generator.generate_pdf(case, case.evidence_items, case.agent_actions, case.mitre_techniques)
    
    return Response(
        content=pdf_bytes, 
        media_type="application/pdf", 
        headers={"Content-Disposition": f"attachment; filename=SOC_Report_{case.id}.pdf"}
    )
@router.get("/graph/entities")
async def get_entity_graph(db: AsyncSession = Depends(get_db)):
    from models.entity import SecurityEntity, SecurityRelationship
    
    # Get all entities
    entities_result = await db.execute(select(SecurityEntity))
    entities = entities_result.scalars().all()
    
    # Get all relationships
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
