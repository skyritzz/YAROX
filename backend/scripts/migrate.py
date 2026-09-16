"""
Database schema bootstrap: the only component that creates or alters the schema.

  * Empty database (no application tables, no alembic_version):
        the historical migration chain cannot build a schema from scratch
        (docs/YAROX_REALITY_AUDIT.md, X-5), so the schema is created from the ORM
        models and stamped at the current migration head.
  * Existing database: ``alembic upgrade head``.
  * Application tables present but no alembic_version: refuse to guess; exit non-zero.

Usage: python -m scripts.migrate
"""
import asyncio
import os
import sys
from typing import Optional

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def alembic_config(database_url: Optional[str] = None) -> Config:
    cfg = Config(os.path.join(BACKEND_DIR, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND_DIR, "alembic"))
    if database_url:
        cfg.attributes["database_url"] = database_url
    return cfg


async def _existing_tables(database_url: str) -> set:
    engine = create_async_engine(database_url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            return set(await conn.run_sync(lambda sync_conn: inspect(sync_conn).get_table_names()))
    finally:
        await engine.dispose()


async def _create_schema_from_models(database_url: str) -> None:
    import models  # noqa: F401
    from models.base import Base

    engine = create_async_engine(database_url, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    finally:
        await engine.dispose()


def bootstrap(database_url: str) -> str:
    """Brings the database to the migration head. Returns the action taken."""
    tables = asyncio.run(_existing_tables(database_url))
    cfg = alembic_config(database_url)
    if not tables:
        asyncio.run(_create_schema_from_models(database_url))
        command.stamp(cfg, "head")
        return "created-from-models-and-stamped"
    if "alembic_version" not in tables:
        raise RuntimeError(
            "Database has application tables but no alembic_version; refusing to modify an unversioned schema."
        )
    command.upgrade(cfg, "head")
    return "upgraded"


def main() -> int:
    from core.config import settings

    try:
        action = bootstrap(settings.DATABASE_URL)
    except Exception as e:
        print(f"[migrate] FAILED: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(f"[migrate] database schema ready ({action})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
