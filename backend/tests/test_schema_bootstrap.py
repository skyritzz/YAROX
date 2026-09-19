"""
The schema is owned by scripts/migrate.py; the application never creates tables implicitly.
"""
import asyncio

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

import models  # noqa: F401
from api.main import startup_event
from database.session import AsyncSessionLocal
from models.base import Base
from scripts.migrate import alembic_config, bootstrap
from tests.support.baseline_schema import BASELINE_REVISION, create_baseline_schema
from tests.test_migrations import MIGRATION_DB, _drop_database, _recreate_database, _url_for

HEAD = ScriptDirectory.from_config(alembic_config()).get_current_head()
URL = _url_for(MIGRATION_DB, "postgresql+asyncpg")


async def _schema_state():
    engine = create_async_engine(URL, poolclass=NullPool)
    async with engine.connect() as conn:
        diffs = await conn.run_sync(lambda c: compare_metadata(MigrationContext.configure(c), Base.metadata))
        version = (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar_one()
    await engine.dispose()
    return diffs, version


@pytest.mark.asyncio
async def test_bootstrap_builds_empty_database_at_head():
    """
    X-5 fix: bootstrap() used to build an empty database via Base.metadata.create_all()
    + `alembic stamp head` (concealing that the real migration chain couldn't do this
    itself - see docs/YAROX_REALITY_AUDIT.md X-5 and tests/test_migration_genesis.py
    for the dedicated regression test of the chain itself). Now that the chain has a
    genesis migration, bootstrap() always just runs `alembic upgrade head` - the
    branch this test used to exercise no longer exists.
    """
    await _recreate_database(MIGRATION_DB)
    try:
        action = await asyncio.to_thread(bootstrap, URL)
        diffs, version = await _schema_state()
        assert action == "upgraded"
        assert version == HEAD
        assert diffs == []
    finally:
        await _drop_database(MIGRATION_DB)


@pytest.mark.asyncio
async def test_bootstrap_upgrades_versioned_database():
    await _recreate_database(MIGRATION_DB)
    try:
        engine = create_async_engine(URL, poolclass=NullPool)
        async with engine.begin() as conn:
            await conn.run_sync(lambda c: create_baseline_schema(Operations(MigrationContext.configure(c))))
        await engine.dispose()
        from alembic import command
        await asyncio.to_thread(command.stamp, alembic_config(URL), BASELINE_REVISION)

        action = await asyncio.to_thread(bootstrap, URL)
        diffs, version = await _schema_state()
        assert action == "upgraded"
        assert version == HEAD
        assert diffs == []
    finally:
        await _drop_database(MIGRATION_DB)


@pytest.mark.asyncio
async def test_bootstrap_refuses_unversioned_schema():
    await _recreate_database(MIGRATION_DB)
    try:
        engine = create_async_engine(URL, poolclass=NullPool)
        async with engine.begin() as conn:
            await conn.execute(text("CREATE TABLE events (id uuid primary key)"))
        await engine.dispose()
        with pytest.raises(RuntimeError, match="no alembic_version"):
            await asyncio.to_thread(bootstrap, URL)
    finally:
        await _drop_database(MIGRATION_DB)


@pytest.mark.asyncio
async def test_application_startup_refuses_outdated_schema_and_creates_nothing():
    async with AsyncSessionLocal() as session:
        await session.execute(text("UPDATE alembic_version SET version_num = :v"), {"v": BASELINE_REVISION})
        await session.commit()
    try:
        with pytest.raises(RuntimeError, match="Database schema not ready"):
            await startup_event()
    finally:
        async with AsyncSessionLocal() as session:
            await session.execute(text("UPDATE alembic_version SET version_num = :v"), {"v": HEAD})
            await session.commit()
