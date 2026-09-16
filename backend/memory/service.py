import uuid
from typing import List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from fastembed import TextEmbedding
from core.config import settings
from memory.vector_repository import IVectorRepository, QdrantRepository
from models.investigation import InvestigationMemory
from schemas.memory import InvestigationKnowledgeObject, InvestigationFingerprint, SimilarityResult
import json

class InvestigationMemoryService:
    def __init__(self, vector_repo: IVectorRepository, embedding_model: TextEmbedding | None = None):
        self.vector_repo = vector_repo
        # The embedding model is loop-independent and expensive to load, so it can be shared
        self.embedding_model = embedding_model or TextEmbedding(model_name="BAAI/bge-small-en-v1.5")

    async def initialize(self):
        await self.vector_repo.initialize()

    async def index_knowledge(self, db: AsyncSession, knowledge: InvestigationKnowledgeObject, fingerprint: InvestigationFingerprint) -> None:
        # Embed the knowledge (e.g. combination of summary and attack story)
        text_to_embed = f"{knowledge.investigation.summary} {knowledge.timeline.attack_story or ''}"
        embeddings = list(self.embedding_model.embed([text_to_embed]))[0].tolist()

        qdrant_id = str(uuid.uuid4())
        knowledge.metadata.qdrant_id = qdrant_id
        
        # Prepare Qdrant payload with rich metadata for filtering
        payload = {
            "investigation_id": knowledge.metadata.investigation_id,
            "severity": knowledge.investigation.severity,
            "risk_score": knowledge.investigation.risk_score,
            "attack_type": knowledge.attack.attack_type,
            "campaign": knowledge.attack.campaign,
            "malware_family": knowledge.attack.malware_family,
            "mitre_techniques": knowledge.attack.mitre_techniques,
            "affected_assets": knowledge.evidence.hosts + knowledge.evidence.users,
            "ioc_count": len(knowledge.evidence.ips) + len(knowledge.evidence.domains) + len(knowledge.evidence.hashes),
            "created_at": knowledge.metadata.created_at.isoformat(),
            "summary": knowledge.investigation.summary,
            "recommendations": knowledge.recommendations.immediate_actions + knowledge.recommendations.long_term_actions
        }

        # Save to Qdrant
        await self.vector_repo.upsert(
            id=qdrant_id,
            vector=embeddings,
            payload=payload
        )

        # Archive old versions if any
        existing_mem_res = await db.execute(
            select(InvestigationMemory).where(InvestigationMemory.investigation_id == knowledge.metadata.investigation_id)
        )
        existing_mem = existing_mem_res.scalar_one_or_none()
        
        version = 1
        if existing_mem:
            version = existing_mem.knowledge_version + 1
            existing_mem.is_latest = False
            
        knowledge.metadata.knowledge_version = version

        # Save to PostgreSQL
        new_memory = InvestigationMemory(
            investigation_id=knowledge.metadata.investigation_id,
            knowledge_version=version,
            is_latest=True,
            knowledge_object=knowledge.model_dump(mode="json"),
            fingerprint=fingerprint.model_dump(mode="json"),
            embedding_model=knowledge.metadata.embedding_model,
            llm_model=knowledge.metadata.llm_model,
            generated_at=knowledge.metadata.generated_at,
            qdrant_id=qdrant_id
        )
        db.add(new_memory)
        await db.commit()

    async def find_similar_cases(self, db: AsyncSession, current_fingerprint: InvestigationFingerprint, current_summary: str, limit: int = 5) -> List[SimilarityResult]:
        embeddings = list(self.embedding_model.embed([current_summary]))[0].tolist()
        
        # 1. Semantic Search
        vector_results = await self.vector_repo.search(vector=embeddings, limit=limit * 2)
        
        similarity_results = []
        for hit in vector_results:
            hit_inv_id = hit.get("investigation_id")
            if not hit_inv_id:
                continue

            # Load full KnowledgeObject from Postgres to calculate overlap
            mem_res = await db.execute(
                select(InvestigationMemory).where(
                    (InvestigationMemory.investigation_id == hit_inv_id) & 
                    (InvestigationMemory.is_latest == True)
                )
            )
            mem_record = mem_res.scalar_one_or_none()
            if not mem_record:
                continue
                
            past_knowledge = InvestigationKnowledgeObject(**mem_record.knowledge_object)
            past_fingerprint = InvestigationFingerprint(**mem_record.fingerprint)
            
            # 2. Hybrid Scoring Logic
            semantic_score = hit.get("_semantic_score", 0.0)
            
            # MITRE Overlap
            mitre_overlap = set(current_fingerprint.mitre_techniques) & set(past_fingerprint.mitre_techniques)
            mitre_score = len(mitre_overlap) / max(len(current_fingerprint.mitre_techniques), 1) if current_fingerprint.mitre_techniques else 0.0
            
            # IOC Hash Match (Exact)
            ioc_score = 1.0 if current_fingerprint.ioc_hash == past_fingerprint.ioc_hash else 0.0
            
            # Attack Type Match
            attack_match = (current_fingerprint.attack_type == past_fingerprint.attack_type) and current_fingerprint.attack_type is not None
            campaign_match = (current_fingerprint.campaign == past_fingerprint.campaign) and current_fingerprint.campaign is not None
            
            # Weighted Total
            total_score = (semantic_score * 0.5) + (mitre_score * 0.2) + (ioc_score * 0.15)
            if attack_match: total_score += 0.05
            if campaign_match: total_score += 0.1
            
            similarity_results.append(SimilarityResult(
                investigation_id=hit_inv_id,
                similarity_score=total_score,
                semantic_score=semantic_score,
                mitre_overlap_score=mitre_score,
                ioc_overlap_score=ioc_score,
                attack_type_match=attack_match,
                campaign_match=campaign_match,
                knowledge_object=past_knowledge
            ))
            
        # Sort by total score
        similarity_results.sort(key=lambda x: x.similarity_score, reverse=True)
        return similarity_results[:limit]

# Singleton instance (connection settings come from application configuration)
memory_service = InvestigationMemoryService(
    QdrantRepository(url=settings.QDRANT_URL, collection_name=settings.QDRANT_COLLECTION)
)
