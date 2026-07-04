import uuid
from typing import List, Dict, Any
from qdrant_client import AsyncQdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from fastembed import TextEmbedding

class MemoryService:
    def __init__(self, url="http://qdrant:6333", collection_name="investigations"):
        self.qdrant = AsyncQdrantClient(url=url)
        self.collection_name = collection_name
        self.embedding_model = TextEmbedding(model_name="BAAI/bge-small-en-v1.5")
    
    async def initialize(self):
        exists = await self.qdrant.collection_exists(self.collection_name)
        if not exists:
            await self.qdrant.create_collection(
                collection_name=self.collection_name,
                vectors_config=VectorParams(size=384, distance=Distance.COSINE),
            )

    async def store_case(self, case_id: str, attack_pattern: str, agent_decision: str, resolution: str, false_positive_status: bool):
        text_to_embed = f"Pattern: {attack_pattern} | Decision: {agent_decision} | Resolution: {resolution}"
        # fastembed returns an iterator, need to cast to list
        embeddings = list(self.embedding_model.embed([text_to_embed]))
        
        point = PointStruct(
            id=str(uuid.uuid4()),
            vector=embeddings[0].tolist(),
            payload={
                "case_id": str(case_id),
                "attack_pattern": attack_pattern,
                "agent_decision": agent_decision,
                "resolution": resolution,
                "false_positive_status": false_positive_status
            }
        )
        
        await self.qdrant.upsert(
            collection_name=self.collection_name,
            points=[point]
        )

    async def similar_cases(self, current_pattern: str, limit: int = 3) -> List[Dict[str, Any]]:
        embeddings = list(self.embedding_model.embed([current_pattern]))
        
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                res = await client.post(
                    f"http://qdrant:6333/collections/{self.collection_name}/points/search",
                    json={
                        "vector": embeddings[0].tolist(),
                        "limit": limit,
                        "with_payload": True
                    }
                )
                res.raise_for_status()
                data = res.json()
                return [hit["payload"] for hit in data.get("result", []) if "payload" in hit]
        except Exception as e:
            print(f"Qdrant search error: {e}")
            return []

memory_service = MemoryService()
