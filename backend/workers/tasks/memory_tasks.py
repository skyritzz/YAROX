import asyncio
from workers.celery_app import celery_app
from core.config import settings
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool
from memory.knowledge_builder import knowledge_builder
from memory.service import memory_service, InvestigationMemoryService
from memory.vector_repository import QdrantRepository
import traceback

@celery_app.task(name="tasks.index_resolved_investigation_task")
def index_resolved_investigation_task(case_id: str):
    async def _run_indexing():
        # Create a fresh NullPool engine for this asyncio.run event loop.
        # This prevents asyncpg connection reuse across different event loops in Celery worker processes.
        task_engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool, echo=False)
        TaskSessionLocal = async_sessionmaker(task_engine, class_=AsyncSession, expire_on_commit=False)

        # Task-local Qdrant client bound to this asyncio.run event loop. The process-global
        # memory_service must not be mutated: its client belongs to another event loop.
        task_memory_service = InvestigationMemoryService(
            QdrantRepository(
                url=memory_service.vector_repo.url,
                collection_name=memory_service.vector_repo.collection_name
            ),
            embedding_model=memory_service.embedding_model
        )
        try:
            async with TaskSessionLocal() as session:
                print(f"Starting memory indexing for case {case_id}")
                await task_memory_service.initialize()
                knowledge_obj, fingerprint = await knowledge_builder.build(session, case_id)
                await task_memory_service.index_knowledge(session, knowledge_obj, fingerprint)
                print(f"Successfully indexed case {case_id}")
        except Exception as e:
            print(f"Failed to index case {case_id}: {e}")
            traceback.print_exc()
        finally:
            await task_engine.dispose()

    asyncio.run(_run_indexing())


