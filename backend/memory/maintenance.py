"""
Memory consistency maintenance.

PostgreSQL is authoritative: a vector is only legitimate when it is the point of the
latest, vector-indexed InvestigationMemory record of an investigation. Anything else in
Qdrant (orphans from failed or deleted runs, superseded versions) is removed here.
"""
import logging
from typing import Any, Dict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.investigation import InvestigationCase, InvestigationMemory, InvestigationStatus

logger = logging.getLogger("yarox.memory")


async def memory_status(session: AsyncSession, service) -> Dict[str, Any]:
    resolved_cases = (await session.execute(
        select(InvestigationCase.id).where(InvestigationCase.status == InvestigationStatus.RESOLVED)
    )).scalars().all()
    latest_records = (await session.execute(
        select(InvestigationMemory).where(InvestigationMemory.is_latest.is_(True))
    )).scalars().all()
    indexed = [r for r in latest_records if r.vector_indexed_at is not None]
    pending = [r for r in latest_records if r.vector_indexed_at is None]
    point_ids = set(await service.vector_repo.list_point_ids())
    valid_point_ids = {r.qdrant_id for r in indexed}

    indexed_case_ids = {str(r.investigation_id) for r in indexed}
    return {
        "collection": service.vector_repo.collection_name,
        "resolved_cases": len(resolved_cases),
        "resolved_cases_indexed": len([c for c in resolved_cases if str(c) in indexed_case_ids]),
        "resolved_cases_not_indexed": [str(c) for c in resolved_cases if str(c) not in indexed_case_ids],
        "latest_memory_records": len(latest_records),
        "vector_indexed_records": len(indexed),
        "pending_records": [str(r.investigation_id) for r in pending],
        "qdrant_points": len(point_ids),
        "orphan_points": len(point_ids - valid_point_ids),
        "missing_points": len(valid_point_ids - point_ids),
    }


async def reconcile_memory(session: AsyncSession, service) -> Dict[str, Any]:
    """
    Deletes vectors with no corresponding latest record and re-writes vectors for
    records that are missing one (pending, or lost from the vector store).
    """
    latest_records = (await session.execute(
        select(InvestigationMemory).where(InvestigationMemory.is_latest.is_(True))
    )).scalars().all()
    point_ids = set(await service.vector_repo.list_point_ids())
    valid_point_ids = {r.qdrant_id for r in latest_records if r.vector_indexed_at is not None}

    orphans = sorted(point_ids - valid_point_ids)
    if orphans:
        await service.vector_repo.delete(orphans)
        logger.info("Deleted %d orphaned memory vectors", len(orphans))

    repaired = []
    for record in latest_records:
        if record.vector_indexed_at is None or record.qdrant_id not in point_ids:
            await service._write_vector(session, record)
            repaired.append(str(record.investigation_id))

    return {"deleted_orphan_points": len(orphans), "repaired_records": repaired}
