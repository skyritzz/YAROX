"""align audit_logs/case_notes with ORM models

Revision ID: 64fc2b276e5a
Revises: e5f6a7b8c9d0
Create Date: 2026-09-20 12:30:00.000000

Found while building and validating the new genesis migration
(``6b66f0fdb4f3``) for a fresh, empty database: ``7a3e8b1d9c4f``'s own
``upgrade()`` declares ``audit_logs.timestamp``/``case_notes.created_at`` as
``nullable=False`` and their four foreign keys (``audit_logs.case_id``,
``audit_logs.user_id``, ``case_notes.case_id``, ``case_notes.user_id``) with
``ondelete='CASCADE'``/``ondelete='SET NULL'`` — but ``models/investigation.py``'s
``AuditLog``/``CaseNote`` classes declare these columns with the plain
SQLAlchemy defaults (nullable, no ``ondelete``).

This was never previously visible: every real database this project has ever
run against got these two tables from ``Base.metadata.create_all()`` (which
follows the models, not the migration text — see the ``scripts/migrate.py``
docstring and the Phase 3 restoration log's "create_all created tables before
the migration" incident), never by literally executing ``7a3e8b1d9c4f``'s DDL.
Confirmed empirically: the real dev database's ``audit_logs``/``case_notes``
foreign keys are ``confdeltype = 'a'`` (NO ACTION, i.e. no ``ondelete``) and
both columns accept NULL — matching the models, not the migration file.

This migration aligns the schema with what the models (and every real
database) already say is correct, so a genuinely fresh install (which, as of
``6b66f0fdb4f3``, now actually executes ``7a3e8b1d9c4f``'s literal DDL for the
first time) ends up identical to an existing one instead of introducing a new
divergence. It is intentionally a separate, additive migration rather than an
edit to ``7a3e8b1d9c4f`` itself, so history is not rewritten. Both operations
are safe no-ops on a database that already matches the models (dropping a
NOT NULL constraint that isn't there, or an ondelete clause that isn't there,
is not what happens here — the column/constraint already has the value this
migration sets), which is the case for every currently-real installation.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '64fc2b276e5a'
down_revision: Union[str, None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column('audit_logs', 'timestamp', existing_type=sa.DateTime(timezone=True), nullable=True)
    op.alter_column('case_notes', 'created_at', existing_type=sa.DateTime(timezone=True), nullable=True)

    op.drop_constraint('audit_logs_case_id_fkey', 'audit_logs', type_='foreignkey')
    op.create_foreign_key('audit_logs_case_id_fkey', 'audit_logs', 'investigation_cases', ['case_id'], ['id'])
    op.drop_constraint('audit_logs_user_id_fkey', 'audit_logs', type_='foreignkey')
    op.create_foreign_key('audit_logs_user_id_fkey', 'audit_logs', 'users', ['user_id'], ['id'])

    op.drop_constraint('case_notes_case_id_fkey', 'case_notes', type_='foreignkey')
    op.create_foreign_key('case_notes_case_id_fkey', 'case_notes', 'investigation_cases', ['case_id'], ['id'])
    op.drop_constraint('case_notes_user_id_fkey', 'case_notes', type_='foreignkey')
    op.create_foreign_key('case_notes_user_id_fkey', 'case_notes', 'users', ['user_id'], ['id'])


def downgrade() -> None:
    op.drop_constraint('case_notes_user_id_fkey', 'case_notes', type_='foreignkey')
    op.create_foreign_key('case_notes_user_id_fkey', 'case_notes', 'users', ['user_id'], ['id'], ondelete='CASCADE')
    op.drop_constraint('case_notes_case_id_fkey', 'case_notes', type_='foreignkey')
    op.create_foreign_key('case_notes_case_id_fkey', 'case_notes', 'investigation_cases', ['case_id'], ['id'], ondelete='CASCADE')

    op.drop_constraint('audit_logs_user_id_fkey', 'audit_logs', type_='foreignkey')
    op.create_foreign_key('audit_logs_user_id_fkey', 'audit_logs', 'users', ['user_id'], ['id'], ondelete='SET NULL')
    op.drop_constraint('audit_logs_case_id_fkey', 'audit_logs', type_='foreignkey')
    op.create_foreign_key('audit_logs_case_id_fkey', 'audit_logs', 'investigation_cases', ['case_id'], ['id'], ondelete='CASCADE')

    op.alter_column('case_notes', 'created_at', existing_type=sa.DateTime(timezone=True), nullable=False)
    op.alter_column('audit_logs', 'timestamp', existing_type=sa.DateTime(timezone=True), nullable=False)
