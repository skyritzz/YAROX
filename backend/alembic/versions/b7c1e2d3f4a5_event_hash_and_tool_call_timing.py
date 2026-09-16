"""event integrity hash and measured tool call timing

Revision ID: b7c1e2d3f4a5
Revises: 7a3e8b1d9c4f
Create Date: 2026-09-17

- events.payload_sha256: SHA-256 over canonical event content (core/integrity.py).
  Existing rows stay NULL; no hash is fabricated for previously stored events.
- agent_tool_calls.started_at / completed_at / error_message: measured tool execution.
- Creates investigation_cases assignment/resolution indexes if missing. Revision
  7a3e8b1d9c4f declared them, but databases whose tables were created by
  ``create_all`` before that migration ran do not have them.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b7c1e2d3f4a5'
down_revision: Union[str, None] = '7a3e8b1d9c4f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('events', sa.Column('payload_sha256', sa.String(length=64), nullable=True))
    op.create_index(op.f('ix_events_payload_sha256'), 'events', ['payload_sha256'], unique=False)

    op.add_column('agent_tool_calls', sa.Column('started_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('agent_tool_calls', sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('agent_tool_calls', sa.Column('error_message', sa.Text(), nullable=True))

    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_investigation_cases_assigned_to_user_id "
        "ON investigation_cases (assigned_to_user_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_investigation_cases_resolved_by_user_id "
        "ON investigation_cases (resolved_by_user_id)"
    )


def downgrade() -> None:
    op.drop_column('agent_tool_calls', 'error_message')
    op.drop_column('agent_tool_calls', 'completed_at')
    op.drop_column('agent_tool_calls', 'started_at')

    op.drop_index(op.f('ix_events_payload_sha256'), table_name='events')
    op.drop_column('events', 'payload_sha256')
