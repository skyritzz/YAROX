"""
Test isolation for the YAROX backend.

This module is imported by pytest before any test module, so the environment
overrides below take effect before ``core.config.settings`` is instantiated.

Isolation guarantees:
  * PostgreSQL: all tests use a dedicated ``<dev database>_test`` database.
    The session aborts if the configured database name does not end in ``_test``.
  * Qdrant: the application collection is ``test_investigation_memory``; all
    ``test_`` prefixed collections are removed at session start and end.
  * Redis / Celery: tests use Redis logical DB 15 as broker, result backend and
    rate-limiter store. The development Celery worker consumes DB 0 only, so
    tasks dispatched by tests can never reach it. Tests that need a task to run
    start an in-process worker bound to DB 15 (see ``tests/support/celery.py``).
"""
import asyncio
import os
from urllib.parse import urlsplit, urlunsplit

import pytest

TEST_REDIS_DB = 15
TEST_QDRANT_PREFIX = "test_"


def _with_database(url: str, database: str) -> str:
    parts = urlsplit(url)
    return urlunsplit(parts._replace(path=f"/{database}"))


def _with_redis_db(url: str, db: int) -> str:
    parts = urlsplit(url)
    return urlunsplit(parts._replace(path=f"/{db}"))


_dev_database_url = os.environ.get(
    "DATABASE_URL", "postgresql+asyncpg://yarox:yaroxpassword@postgres:5432/yarox"
)
_dev_db_name = urlsplit(_dev_database_url).path.lstrip("/")
_test_database_url = os.environ.get("TEST_DATABASE_URL") or _with_database(
    _dev_database_url, f"{_dev_db_name}_test"
)
_test_redis_url = _with_redis_db(os.environ.get("REDIS_URL", "redis://redis:6379/0"), TEST_REDIS_DB)

# Exposed only so the isolation test can prove the development database is untouched.
os.environ["YAROX_DEV_DATABASE_URL"] = _dev_database_url

os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = _test_database_url
os.environ["REDIS_URL"] = _test_redis_url
os.environ["CELERY_BROKER_URL"] = _test_redis_url
os.environ["CELERY_RESULT_BACKEND"] = _test_redis_url
os.environ["QDRANT_COLLECTION"] = f"{TEST_QDRANT_PREFIX}investigation_memory"


def _assert_isolated_configuration():
    from core.config import settings

    db_name = urlsplit(settings.DATABASE_URL).path.lstrip("/")
    if not db_name.endswith("_test"):
        pytest.exit(f"Refusing to run tests against non-test database '{db_name}'", returncode=2)
    if urlsplit(settings.REDIS_URL).path != f"/{TEST_REDIS_DB}":
        pytest.exit(f"Refusing to run tests against non-test Redis DB '{settings.REDIS_URL}'", returncode=2)
    if not settings.QDRANT_COLLECTION.startswith(TEST_QDRANT_PREFIX):
        pytest.exit(f"Refusing to run tests against Qdrant collection '{settings.QDRANT_COLLECTION}'", returncode=2)


async def _prepare_test_database():
    import asyncpg
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import NullPool
    from sqlalchemy import text
    from core.config import settings
    import models  # noqa: F401  (registers all tables on Base.metadata)
    from models.base import Base

    parts = urlsplit(settings.DATABASE_URL)
    db_name = parts.path.lstrip("/")
    maintenance_dsn = urlunsplit(parts._replace(scheme="postgresql", path="/postgres"))
    conn = await asyncpg.connect(maintenance_dsn)
    try:
        exists = await conn.fetchval("SELECT 1 FROM pg_database WHERE datname = $1", db_name)
        if not exists:
            await conn.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        await conn.close()

    engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool)
    async with engine.begin() as connection:
        await connection.execute(text("DROP SCHEMA public CASCADE"))
        await connection.execute(text("CREATE SCHEMA public"))
        await connection.execute(text("GRANT USAGE ON SCHEMA public TO PUBLIC"))
        await connection.run_sync(Base.metadata.create_all)
    await engine.dispose()


def _stamp_alembic_head():
    from alembic import command
    from alembic.config import Config

    backend_dir = os.path.dirname(os.path.abspath(__file__))
    cfg = Config(os.path.join(backend_dir, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
    command.stamp(cfg, "head")


async def _purge_test_qdrant_collections():
    from qdrant_client import AsyncQdrantClient
    from core.config import settings

    client = AsyncQdrantClient(url=settings.QDRANT_URL)
    try:
        collections = await client.get_collections()
        for collection in collections.collections:
            if collection.name.startswith(TEST_QDRANT_PREFIX):
                await client.delete_collection(collection.name)
    finally:
        await client.close()


def _flush_test_redis():
    import redis
    from core.config import settings

    assert urlsplit(settings.REDIS_URL).path == f"/{TEST_REDIS_DB}"
    client = redis.Redis.from_url(settings.REDIS_URL)
    try:
        client.flushdb()
    finally:
        client.close()


@pytest.fixture(scope="session")
def event_loop():
    """
    One event loop for the whole session, matching production where each
    process runs a single loop. Module-level async clients (the SQLAlchemy
    engine pool, the Qdrant client) are bound to the loop they first run on.
    """
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session", autouse=True)
def isolated_test_infrastructure():
    _assert_isolated_configuration()
    asyncio.run(_prepare_test_database())
    _stamp_alembic_head()
    asyncio.run(_purge_test_qdrant_collections())
    _flush_test_redis()
    yield
    asyncio.run(_purge_test_qdrant_collections())
    _flush_test_redis()
