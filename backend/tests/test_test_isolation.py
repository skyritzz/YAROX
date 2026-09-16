"""
Proves the test suite cannot modify development data.
"""
import os
import uuid
from urllib.parse import urlsplit

import asyncpg
import pytest
from sqlalchemy import select

from core.config import settings
from database.session import AsyncSessionLocal, engine
from memory.service import memory_service
from models.investigation import InvestigationCase, InvestigationStatus, Severity
from workers.celery_app import celery_app


def _db_name(url: str) -> str:
    return urlsplit(url).path.lstrip("/")


def test_application_settings_point_at_isolated_infrastructure():
    dev_url = os.environ["YAROX_DEV_DATABASE_URL"]
    assert _db_name(settings.DATABASE_URL).endswith("_test")
    assert _db_name(settings.DATABASE_URL) != _db_name(dev_url)
    assert engine.url.database == _db_name(settings.DATABASE_URL)

    assert urlsplit(settings.REDIS_URL).path == "/15"
    assert celery_app.conf.broker_url.endswith("/15")
    assert celery_app.conf.result_backend.endswith("/15")

    assert settings.QDRANT_COLLECTION.startswith("test_")
    assert memory_service.vector_repo.collection_name == settings.QDRANT_COLLECTION


@pytest.mark.asyncio
async def test_writes_land_in_test_database_and_never_in_development_database():
    marker_id = uuid.uuid4()
    async with AsyncSessionLocal() as session:
        session.add(InvestigationCase(
            id=marker_id,
            title="isolation-marker",
            status=InvestigationStatus.OPEN,
            severity=Severity.LOW,
        ))
        await session.commit()

    async with AsyncSessionLocal() as session:
        found = (await session.execute(
            select(InvestigationCase).where(InvestigationCase.id == marker_id)
        )).scalar_one_or_none()
        assert found is not None

    # Read-only check against the development database.
    dev_parts = urlsplit(os.environ["YAROX_DEV_DATABASE_URL"])
    dev_dsn = dev_parts._replace(scheme="postgresql").geturl()
    conn = await asyncpg.connect(dev_dsn)
    try:
        leaked = await conn.fetchval(
            "SELECT count(*) FROM investigation_cases WHERE id = $1", marker_id
        )
    finally:
        await conn.close()
    assert leaked == 0
