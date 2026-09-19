"""
Database schema bootstrap: the only component that creates or alters the schema.

  * Empty database (no tables at all): ``alembic upgrade head`` builds the
    complete schema from the genesis migration (``6b66f0fdb4f3``) forward.
    Before that migration existed, the historical chain could not build a
    schema from scratch (docs/YAROX_REALITY_AUDIT.md, X-5) and this bootstrap
    used to paper over it with ``Base.metadata.create_all`` + ``alembic stamp
    head`` — that fallback is gone now that the chain is actually fixed; see
    docs/MIGRATION_REMEDIATION_PROPOSAL.md for the fix and
    tests/test_migration_genesis.py for the regression test that would fail
    if this chain broke again.
  * Existing database, already versioned: ``alembic upgrade head`` applies
    only whatever is newer than its current stamp.
  * Application tables present but no alembic_version: refuse to guess; exit
    non-zero rather than silently stamping an unknown schema.

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


def bootstrap(database_url: str) -> str:
    """Brings the database to the migration head via Alembic. Returns the action taken."""
    tables = asyncio.run(_existing_tables(database_url))
    cfg = alembic_config(database_url)
    if tables and "alembic_version" not in tables:
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
