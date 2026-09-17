import asyncio
import logging

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool
from sqlalchemy import select

from workers.celery_app import celery_app
from core.config import settings
from memory.service import memory_service, InvestigationMemoryService
from memory.vector_repository import QdrantRepository
from models.investigation import InvestigationCase, InvestigationStatus

logger = logging.getLogger("yarox.memory")


def _task_memory_service() -> InvestigationMemoryService:
    """
    Task-local Qdrant client bound to this task's event loop. The process-global
    memory_service must not be mutated: its client belongs to another event loop.
    """
    return InvestigationMemoryService(
        QdrantRepository(
            url=memory_service.vector_repo.url,
            collection_name=memory_service.vector_repo.collection_name,
        ),
        embedding_model=memory_service.embedding_model,
    )


@celery_app.task(
    name="tasks.index_resolved_investigation_task",
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=2,
    retry_backoff_max=300,
    retry_jitter=True,
    max_retries=5,
    acks_late=True,
)
def index_resolved_investigation_task(self, case_id: str):
    """
    Indexes a human-resolved investigation into long-term memory.

    Failures propagate: the task is retried with exponential backoff and ends in the
    FAILURE state if it cannot succeed, so a broken memory pipeline is observable
    instead of silently reporting success.
    """
    async def _run_indexing():
        # Fresh NullPool engine per asyncio.run loop: prevents asyncpg connection reuse
        # across different event loops in Celery worker processes.
        task_engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool, echo=False)
        TaskSessionLocal = async_sessionmaker(task_engine, class_=AsyncSession, expire_on_commit=False)
        service = _task_memory_service()
        try:
            async with TaskSessionLocal() as session:
                case = (await session.execute(
                    select(InvestigationCase).where(InvestigationCase.id == case_id)
                )).scalar_one_or_none()
                if case is None:
                    raise ValueError(f"Investigation {case_id} not found")
                if case.status != InvestigationStatus.RESOLVED:
                    # Human-gated memory: only analyst-resolved cases enter long-term memory
                    logger.warning("Skipping memory indexing for case %s with status %s", case_id, case.status)
                    return {"indexed": False, "reason": f"case status is {case.status.value}"}

                logger.info("Starting memory indexing for case %s", case_id)
                await service.initialize()
                record = await service.index_case(session, case_id)
                logger.info(
                    "Indexed case %s as memory %s version %s (%s)",
                    case_id, record.id, record.knowledge_version, record.knowledge_source,
                )
                return {
                    "indexed": True,
                    "memory_id": str(record.id),
                    "version": record.knowledge_version,
                    "knowledge_source": record.knowledge_source,
                }
        finally:
            await task_engine.dispose()

    try:
        return asyncio.run(_run_indexing())
    except Exception as e:
        logger.exception("Memory indexing failed for case %s: %s", case_id, e)
        raise


@celery_app.task(name="tasks.reconcile_memory_task")
def reconcile_memory_task():
    """Removes orphaned vectors and re-indexes records whose vector is missing."""
    async def _run():
        from memory.maintenance import reconcile_memory

        task_engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool, echo=False)
        TaskSessionLocal = async_sessionmaker(task_engine, class_=AsyncSession, expire_on_commit=False)
        service = _task_memory_service()
        try:
            async with TaskSessionLocal() as session:
                await service.initialize()
                return await reconcile_memory(session, service)
        finally:
            await task_engine.dispose()

    return asyncio.run(_run())
