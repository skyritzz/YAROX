from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Dict, Any

from database.session import get_db
from models.investigation import InvestigationCase, InvestigationStatus
from models.user import User
from core.auth import require_admin, require_authenticated
from memory.maintenance import memory_status, reconcile_memory
from memory.service import memory_service
from workers.tasks.memory_tasks import index_resolved_investigation_task

router = APIRouter()


@router.get("/status", response_model=Dict[str, Any])
async def get_memory_status(
    current_user: User = Depends(require_authenticated),
    db: AsyncSession = Depends(get_db)
):
    """
    Live memory consistency report: resolved cases, indexed records, records pending a
    vector write, orphaned vectors and vectors missing for a record.
    """
    await memory_service.initialize()
    return await memory_status(db, memory_service)


@router.post("/reindex", response_model=Dict[str, Any])
async def reindex_memory(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Dispatches memory indexing for every human-resolved case. Tasks run on the Celery
    worker and fail loudly (with retries) if indexing does not succeed.
    """
    res = await db.execute(
        select(InvestigationCase.id).where(InvestigationCase.status == InvestigationStatus.RESOLVED)
    )
    resolved_cases = res.scalars().all()

    dispatched = []
    for case_id in resolved_cases:
        task = index_resolved_investigation_task.delay(str(case_id))
        dispatched.append({"case_id": str(case_id), "task_id": task.id})

    return {"message": f"Dispatched memory indexing for {len(dispatched)} resolved cases", "tasks": dispatched}


@router.post("/reconcile", response_model=Dict[str, Any])
async def reconcile(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Deletes orphaned vectors and re-writes vectors missing for latest memory records."""
    await memory_service.initialize()
    return await reconcile_memory(db, memory_service)
