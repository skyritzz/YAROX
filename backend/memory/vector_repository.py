from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from qdrant_client import AsyncQdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct, ScoredPoint, Filter, FieldCondition, MatchValue, PointIdsList
import uuid

class MemoryBackendError(Exception):
    """Base exception for Qdrant / Vector Memory backend failures."""
    pass

class MemoryBackendUnavailableError(MemoryBackendError):
    """Raised when the vector database cannot be reached."""
    pass

class MemoryBackendAPIError(MemoryBackendError):
    """Raised when the vector database returns an API, schema, or validation error."""
    pass

class IVectorRepository(ABC):
    @abstractmethod
    async def initialize(self) -> None:
        pass

    @abstractmethod
    async def upsert(self, id: str, vector: List[float], payload: Dict[str, Any]) -> None:
        pass

    @abstractmethod
    async def search(self, vector: List[float], limit: int = 5, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    async def delete(self, ids: List[str]) -> None:
        pass

    @abstractmethod
    async def list_point_ids(self) -> List[str]:
        pass

class QdrantRepository(IVectorRepository):
    def __init__(self, url: str = "http://qdrant:6333", collection_name: str = "investigation_memory"):
        self.url = url
        self.collection_name = collection_name
        self.vector_size = 384 # BAAI/bge-small-en-v1.5
        self.qdrant = AsyncQdrantClient(url=url)

    def _handle_exception(self, e: Exception, operation: str) -> None:
        err_msg = str(e).lower()
        network_indicators = (
            "connect", "unreachable", "timeout", "refused", "cannot connect",
            "name or service not known", "not known", "nodename", "gaierror",
            "connection", "network"
        )
        if any(k in err_msg for k in network_indicators):
            raise MemoryBackendUnavailableError(f"Qdrant backend unavailable at {self.url} during {operation}: {str(e)}") from e
        raise MemoryBackendAPIError(f"Qdrant API error during {operation}: {str(e)}") from e

    async def initialize(self) -> None:
        try:
            exists = await self.qdrant.collection_exists(self.collection_name)
            if not exists:
                await self.qdrant.create_collection(
                    collection_name=self.collection_name,
                    vectors_config=VectorParams(size=self.vector_size, distance=Distance.COSINE),
                )
        except Exception as e:
            self._handle_exception(e, "initialize")

    async def upsert(self, id: str, vector: List[float], payload: Dict[str, Any]) -> None:
        try:
            point = PointStruct(
                id=id,
                vector=vector,
                payload=payload
            )
            await self.qdrant.upsert(
                collection_name=self.collection_name,
                points=[point]
            )
        except Exception as e:
            self._handle_exception(e, f"upsert for point {id}")

    async def search(self, vector: List[float], limit: int = 5, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        query_filter = None
        if filters:
            conditions = []
            for k, v in filters.items():
                conditions.append(FieldCondition(key=k, match=MatchValue(value=v)))
            query_filter = Filter(must=conditions)

        try:
            results: List[ScoredPoint] = await self.qdrant.search(
                collection_name=self.collection_name,
                query_vector=vector,
                limit=limit,
                query_filter=query_filter,
                with_payload=True
            )
            
            # Combine payload with semantic score
            hits = []
            for res in results:
                hit = dict(res.payload or {})
                hit["_semantic_score"] = res.score
                hit["_point_id"] = str(res.id)
                hits.append(hit)
                
            return hits
        except Exception as e:
            self._handle_exception(e, "search")

    async def delete(self, ids: List[str]) -> None:
        if not ids:
            return
        try:
            await self.qdrant.delete(collection_name=self.collection_name, points_selector=PointIdsList(points=list(ids)))
        except Exception as e:
            self._handle_exception(e, f"delete of {len(ids)} points")

    async def list_point_ids(self) -> List[str]:
        try:
            if not await self.qdrant.collection_exists(self.collection_name):
                return []
            ids: List[str] = []
            offset = None
            while True:
                points, offset = await self.qdrant.scroll(
                    collection_name=self.collection_name, limit=256, offset=offset,
                    with_payload=False, with_vectors=False,
                )
                ids.extend(str(p.id) for p in points)
                if offset is None:
                    return ids
        except Exception as e:
            self._handle_exception(e, "scroll")
