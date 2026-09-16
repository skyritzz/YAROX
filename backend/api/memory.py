from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Dict, Any

from database.session import get_db
from models.investigation import InvestigationCase, InvestigationStatus
from models.user import User
from core.auth import require_admin
from workers.tasks.memory_tasks import index_resolved_investigation_task

router = APIRouter()

@router.post("/reindex", response_model=Dict[str, Any])
async def reindex_memory(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Triggers a background task to rebuild investigation memory for all human-verified resolved cases.
    """
    res = await db.execute(
        select(InvestigationCase.id).where(InvestigationCase.status == InvestigationStatus.RESOLVED)
    )
    resolved_cases = res.scalars().all()
    
    for case_id in resolved_cases:
        index_resolved_investigation_task.delay(str(case_id))
        
    return {"message": f"Triggered reindexing for {len(resolved_cases)} resolved cases"}
