import pytest
import uuid
from typing import List, Dict, Any

from memory.vector_repository import (
    QdrantRepository,
    MemoryBackendError,
    MemoryBackendUnavailableError,
    MemoryBackendAPIError
)
from schemas.memory import InvestigationKnowledgeObject, InvestigationFingerprint
from memory.service import InvestigationMemoryService

# Live Qdrant integration tests (Unmocked)

@pytest.mark.asyncio
async def test_qdrant_live_collection_lifecycle_write_and_read():
    """
    Real integration test against live Qdrant container (http://qdrant:6333).
    1. Initializes test collection.
    2. Upserts real vector and metadata payload.
    3. Searches for the point and verifies payload integrity and semantic score.
    4. Deletes and cleans up the collection.
    """
    test_collection = f"test_mem_{uuid.uuid4().hex[:8]}"
    repo = QdrantRepository(url="http://qdrant:6333", collection_name=test_collection)
    
    # 1. Initialize collection
    await repo.initialize()
    exists = await repo.qdrant.collection_exists(test_collection)
    assert exists is True
    
    # 2. Insert test point
    point_id = str(uuid.uuid4())
    test_vector = [0.05] * 384
    test_payload = {
        "investigation_id": "case-test-100",
        "attack_type": "Brute Force",
        "severity": "HIGH",
        "summary": "Verified brute force credential compromise",
        "recommendations": ["Reset passwords", "Lock account"]
    }
    await repo.upsert(id=point_id, vector=test_vector, payload=test_payload)
    
    # 3. Query point
    results = await repo.search(vector=test_vector, limit=5)
    assert len(results) == 1
    hit = results[0]
    assert hit["investigation_id"] == "case-test-100"
    assert hit["attack_type"] == "Brute Force"
    assert hit["summary"] == "Verified brute force credential compromise"
    assert hit["_semantic_score"] >= 0.99
    
    # 4. Clean up
    await repo.qdrant.delete_collection(test_collection)
    exists_after = await repo.qdrant.collection_exists(test_collection)
    assert exists_after is False


@pytest.mark.asyncio
async def test_qdrant_truthful_empty_when_no_match():
    """
    Verifies that querying a healthy but empty Qdrant collection returns an empty list [],
    distinguishing empty memory from a backend failure.
    """
    test_collection = f"test_empty_{uuid.uuid4().hex[:8]}"
    repo = QdrantRepository(url="http://qdrant:6333", collection_name=test_collection)
    
    await repo.initialize()
    results = await repo.search(vector=[0.01] * 384, limit=5)
    assert results == []
    
    await repo.qdrant.delete_collection(test_collection)


@pytest.mark.asyncio
async def test_qdrant_unreachable_backend_raises_explicit_unavailable_error():
    """
    Verifies that when Qdrant is unreachable, an explicit MemoryBackendUnavailableError is raised
    rather than silently returning an empty list [].
    """
    unreachable_repo = QdrantRepository(url="http://nonexistent-qdrant-host:9999", collection_name="test")
    
    with pytest.raises(MemoryBackendUnavailableError) as exc_info:
        await unreachable_repo.initialize()
    assert "unavailable" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_qdrant_invalid_vector_size_raises_explicit_api_error():
    """
    Verifies that passing an invalid vector dimension (e.g. 4 dimensions when collection expects 384)
    raises an explicit MemoryBackendAPIError rather than silently returning an empty list [].
    """
    test_collection = f"test_err_{uuid.uuid4().hex[:8]}"
    repo = QdrantRepository(url="http://qdrant:6333", collection_name=test_collection)
    await repo.initialize()
    
    # Intentionally bad vector size (4 elements instead of 384)
    with pytest.raises(MemoryBackendAPIError):
        await repo.search(vector=[0.1, 0.2, 0.3, 0.4], limit=1)
        
    await repo.qdrant.delete_collection(test_collection)
