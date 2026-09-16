"""
Verifies that Alembic migrations after the baseline revision upgrade a real
PostgreSQL database to exactly the schema declared by the ORM models.
"""
import asyncio
import os
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.pool import NullPool

import models  # noqa: F401
from core.config import settings
from models.base import Base
from tests.support.baseline_schema import BASELINE_REVISION, create_baseline_schema

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATION_DB = f"{urlsplit(settings.DATABASE_URL).path.lstrip('/')}_migrations"


def _url_for(database: str, scheme: str) -> str:
    parts = urlsplit(settings.DATABASE_URL)
    return urlunsplit(parts._replace(scheme=scheme, path=f"/{database}"))


async def _recreate_database(name: str):
    assert name.endswith("_test_migrations")
    conn = await asyncpg.connect(_url_for("postgres", "postgresql"))
    try:
        await conn.execute(f'DROP DATABASE IF EXISTS "{name}"')
        await conn.execute(f'CREATE DATABASE "{name}"')
    finally:
        await conn.close()


async def _drop_database(name: str):
    conn = await asyncpg.connect(_url_for("postgres", "postgresql"))
    try:
        await conn.execute(f'DROP DATABASE IF EXISTS "{name}"')
    finally:
        await conn.close()


def _alembic_config(async_url: str) -> Config:
    cfg = Config(os.path.join(BACKEND_DIR, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND_DIR, "alembic"))
    cfg.attributes["database_url"] = async_url
    return cfg


def _run_migration_roundtrip():
    """Runs synchronously (in a worker thread) because alembic's env.py calls asyncio.run."""
    async_url = _url_for(MIGRATION_DB, "postgresql+asyncpg")

    async def build_baseline():
        from sqlalchemy.ext.asyncio import create_async_engine
        engine = create_async_engine(async_url, poolclass=NullPool)
        async with engine.begin() as conn:
            def apply(sync_conn):
                create_baseline_schema(Operations(MigrationContext.configure(sync_conn)))
            await conn.run_sync(apply)
        await engine.dispose()

    asyncio.run(build_baseline())

    cfg = _alembic_config(async_url)
    command.stamp(cfg, BASELINE_REVISION)
    command.upgrade(cfg, "head")

    async def diff_against_models():
        from sqlalchemy.ext.asyncio import create_async_engine
        engine = create_async_engine(async_url, poolclass=NullPool)
        async with engine.connect() as conn:
            def compare(sync_conn):
                return compare_metadata(MigrationContext.configure(sync_conn), Base.metadata)
            diffs = await conn.run_sync(compare)
            version = (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar_one()
        await engine.dispose()
        return diffs, version

    return asyncio.run(diff_against_models())


@pytest.mark.asyncio
async def test_migrations_upgrade_baseline_to_model_schema():
    await _recreate_database(MIGRATION_DB)
    try:
        diffs, version = await asyncio.to_thread(_run_migration_roundtrip)
        script_head = ScriptDirectory.from_config(
            _alembic_config(_url_for(MIGRATION_DB, "postgresql+asyncpg"))
        ).get_current_head()
        assert version == script_head
        assert diffs == [], f"Migrated schema differs from ORM models: {diffs}"
    finally:
        await _drop_database(MIGRATION_DB)
