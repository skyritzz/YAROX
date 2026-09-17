"""investigation memory indexing state and provenance

Revision ID: d4e5f6a7b8c9
Revises: c2d3e4f5a6b7
Create Date: 2026-09-17

- vector_indexed_at: NULL until the Qdrant vector is written (Postgres record is durable first)
- knowledge_source / source_report_id: provenance of the stored knowledge
- at most one latest memory record per investigation
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, None] = 'c2d3e4f5a6b7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('investigation_memory', sa.Column('vector_indexed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('investigation_memory', sa.Column('knowledge_source', sa.String(), nullable=True))
    op.add_column('investigation_memory', sa.Column('source_report_id', sa.UUID(), nullable=True))
    op.create_foreign_key(
        'investigation_memory_source_report_id_fkey', 'investigation_memory',
        'investigation_reports', ['source_report_id'], ['id'],
    )
    op.create_index(
        'uq_investigation_memory_latest', 'investigation_memory', ['investigation_id'],
        unique=True, postgresql_where=sa.text('is_latest'),
    )


def downgrade() -> None:
    op.drop_index('uq_investigation_memory_latest', table_name='investigation_memory')
    op.drop_constraint('investigation_memory_source_report_id_fkey', 'investigation_memory', type_='foreignkey')
    op.drop_column('investigation_memory', 'source_report_id')
    op.drop_column('investigation_memory', 'knowledge_source')
    op.drop_column('investigation_memory', 'vector_indexed_at')
