"""
Investigation memory: durable knowledge records in PostgreSQL, vectors in Qdrant.

Write ordering (no vector may exist without a durable record):
  1. Insert the InvestigationMemory row (``vector_indexed_at = NULL``) and commit.
  2. Upsert the vector into Qdrant using the row ID as the point ID.
  3. Set ``vector_indexed_at`` and commit.
  4. Delete vectors of superseded versions (best effort; stale points never match, see below).
If step 2 fails the row stays pending and the exception propagates; a retry resumes
from the pending row instead of creating another version.

Retrieval only accepts a Qdrant hit when it corresponds to the latest, vector-indexed
record of that investigation, so orphaned or superseded points are never returned.

Similarity score (all components in [0, 1]):
    total = 0.5 * semantic + 0.2 * mitre_overlap + 0.2 * ioc_overlap + 0.1 * asset_overlap
where each overlap is |current ∩ past| / |current| (0 when the current case has none).
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Set

from fastembed import TextEmbedding
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from memory.indicators import CaseIndicators
from memory.vector_repository import IVectorRepository, QdrantRepository
from models.investigation import InvestigationMemory
from schemas.memory import InvestigationFingerprint, InvestigationKnowledgeObject, SimilarityResult

logger = logging.getLogger("yarox.memory")

SCORE_WEIGHTS = {"semantic": 0.5, "mitre": 0.2, "ioc": 0.2, "asset": 0.1}


def _overlap(current: Set[str], past: Set[str]) -> tuple[float, List[str]]:
    if not current:
        return 0.0, []
    shared = current & past
    return len(shared) / len(current), sorted(shared)


def _knowledge_iocs(ko: InvestigationKnowledgeObject) -> Set[str]:
    return set(ko.evidence.ips) | set(ko.evidence.domains) | set(ko.evidence.hashes) | set(ko.evidence.commands)


def _knowledge_assets(ko: InvestigationKnowledgeObject) -> Set[str]:
    return {f"user:{u}" for u in ko.evidence.users} | {f"host:{h}" for h in ko.evidence.hosts}


class InvestigationMemoryService:
    def __init__(self, vector_repo: IVectorRepository, embedding_model: TextEmbedding | None = None):
        self.vector_repo = vector_repo
        # The embedding model is loop-independent and expensive to load, so it can be shared
        self.embedding_model = embedding_model or TextEmbedding(model_name="BAAI/bge-small-en-v1.5")

    async def initialize(self):
        await self.vector_repo.initialize()

    def embed(self, text: str) -> List[float]:
        return list(self.embedding_model.embed([text]))[0].tolist()

    async def index_case(self, db: AsyncSession, case_id: uuid.UUID | str) -> InvestigationMemory:
        """
        Indexes a case, resuming a pending record if a previous attempt stored the
        knowledge but failed to write the vector.
        """
        from memory.knowledge_builder import knowledge_builder

        case_uuid = uuid.UUID(str(case_id))
        latest = (await db.execute(
            select(InvestigationMemory).where(
                InvestigationMemory.investigation_id == case_uuid,
                InvestigationMemory.is_latest.is_(True),
            )
        )).scalar_one_or_none()
        if latest is not None and latest.vector_indexed_at is None:
            logger.info("Resuming pending memory record %s for case %s", latest.id, case_uuid)
            await self._write_vector(db, latest)
            return latest

        knowledge, fingerprint = await knowledge_builder.build(db, case_uuid)
        return await self.index_knowledge(db, knowledge, fingerprint)

    async def index_knowledge(self, db: AsyncSession, knowledge: InvestigationKnowledgeObject, fingerprint: InvestigationFingerprint) -> InvestigationMemory:
        investigation_id = uuid.UUID(knowledge.metadata.investigation_id)

        previous = (await db.execute(
            select(InvestigationMemory).where(InvestigationMemory.investigation_id == investigation_id)
        )).scalars().all()
        superseded_point_ids = [p.qdrant_id for p in previous if p.is_latest]
        version = max((p.knowledge_version or 0) for p in previous) + 1 if previous else 1

        await db.execute(
            update(InvestigationMemory)
            .where(InvestigationMemory.investigation_id == investigation_id, InvestigationMemory.is_latest.is_(True))
            .values(is_latest=False)
        )

        row_id = uuid.uuid4()
        knowledge.metadata.qdrant_id = str(row_id)
        knowledge.metadata.knowledge_version = version
        if not knowledge.metadata.embedding_text:
            knowledge.metadata.embedding_text = f"{knowledge.investigation.title}\n{knowledge.investigation.summary}"

        row = InvestigationMemory(
            id=row_id,
            investigation_id=investigation_id,
            knowledge_version=version,
            is_latest=True,
            knowledge_object=knowledge.model_dump(mode="json"),
            fingerprint=fingerprint.model_dump(mode="json"),
            embedding_model=knowledge.metadata.embedding_model,
            llm_model=knowledge.metadata.llm_model,
            generated_at=knowledge.metadata.generated_at,
            qdrant_id=str(row_id),
            vector_indexed_at=None,
            knowledge_source=knowledge.metadata.knowledge_source,
            source_report_id=uuid.UUID(knowledge.metadata.source_report_id) if knowledge.metadata.source_report_id else None,
        )
        db.add(row)
        await db.commit()  # durable record before any vector exists

        await self._write_vector(db, row)

        if superseded_point_ids:
            try:
                await self.vector_repo.delete(superseded_point_ids)
            except Exception as e:
                logger.warning("Could not delete superseded memory vectors %s: %s", superseded_point_ids, e)
        return row

    async def _write_vector(self, db: AsyncSession, row: InvestigationMemory) -> None:
        knowledge = InvestigationKnowledgeObject(**row.knowledge_object)
        await self.vector_repo.upsert(
            id=row.qdrant_id,
            vector=self.embed(knowledge.metadata.embedding_text),
            payload={
                "investigation_id": str(row.investigation_id),
                "memory_id": str(row.id),
                "knowledge_version": row.knowledge_version,
                "knowledge_source": row.knowledge_source,
                "severity": knowledge.investigation.severity,
                "mitre_techniques": knowledge.attack.mitre_techniques,
                "summary": knowledge.investigation.summary,
            },
        )
        row.vector_indexed_at = datetime.now(timezone.utc)
        await db.commit()

    async def find_similar_cases(
        self,
        db: AsyncSession,
        current_fingerprint: InvestigationFingerprint,
        current_indicators: CaseIndicators,
        query_text: str,
        limit: int = 5,
        exclude_investigation_id: Optional[str] = None,
    ) -> List[SimilarityResult]:
        hits = await self.vector_repo.search(vector=self.embed(query_text), limit=limit * 3 + 1)

        results: dict[str, SimilarityResult] = {}
        current_mitre = set(current_fingerprint.mitre_techniques)
        current_iocs = current_indicators.iocs()
        current_assets = current_indicators.assets()

        for hit in hits:
            investigation_id = hit.get("investigation_id")
            point_id = hit.get("_point_id")
            if not investigation_id or investigation_id == exclude_investigation_id or investigation_id in results:
                continue

            record = (await db.execute(
                select(InvestigationMemory).where(
                    InvestigationMemory.investigation_id == uuid.UUID(investigation_id),
                    InvestigationMemory.is_latest.is_(True),
                    InvestigationMemory.vector_indexed_at.is_not(None),
                )
            )).scalar_one_or_none()
            if record is None or record.qdrant_id != point_id:
                continue  # orphaned or superseded vector

            past = InvestigationKnowledgeObject(**record.knowledge_object)
            semantic = max(0.0, min(1.0, float(hit.get("_semantic_score", 0.0))))
            mitre_score, shared_mitre = _overlap(current_mitre, set(past.attack.mitre_techniques))
            ioc_score, shared_iocs = _overlap(current_iocs, _knowledge_iocs(past))
            asset_score, shared_assets = _overlap(current_assets, _knowledge_assets(past))
            total = (
                SCORE_WEIGHTS["semantic"] * semantic
                + SCORE_WEIGHTS["mitre"] * mitre_score
                + SCORE_WEIGHTS["ioc"] * ioc_score
                + SCORE_WEIGHTS["asset"] * asset_score
            )
            if total < settings.MEMORY_MIN_SIMILARITY:
                continue

            results[investigation_id] = SimilarityResult(
                investigation_id=investigation_id,
                similarity_score=round(total, 4),
                semantic_score=round(semantic, 4),
                mitre_overlap_score=round(mitre_score, 4),
                ioc_overlap_score=round(ioc_score, 4),
                asset_overlap_score=round(asset_score, 4),
                attack_type_match=False,
                campaign_match=False,
                shared_mitre_techniques=shared_mitre,
                shared_iocs=shared_iocs,
                shared_assets=shared_assets,
                knowledge_object=past,
            )

        ranked = sorted(results.values(), key=lambda r: r.similarity_score, reverse=True)
        return ranked[:limit]


# Singleton instance (connection settings come from application configuration)
memory_service = InvestigationMemoryService(
    QdrantRepository(url=settings.QDRANT_URL, collection_name=settings.QDRANT_COLLECTION)
)
