"""attack technique confidence becomes nullable

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-09-18

Technique confidence used to be a constant (0.8 for rule matches, 0.9 for agent
mappings). It now carries meaning: 1.0 for a deterministic rule match, NULL for an
agent-proposed mapping that was validated against the ATT&CK knowledge base and cited
evidence but has no measured confidence.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column('attack_techniques', 'confidence', existing_type=sa.Float(), nullable=True)


def downgrade() -> None:
    op.execute("UPDATE attack_techniques SET confidence = 1.0 WHERE confidence IS NULL")
    op.alter_column('attack_techniques', 'confidence', existing_type=sa.Float(), nullable=False)
