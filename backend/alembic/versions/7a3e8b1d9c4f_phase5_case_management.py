"""phase5 case management

Revision ID: 7a3e8b1d9c4f
Revises: 8532d6f9c999
Create Date: 2026-08-23 23:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '7a3e8b1d9c4f'
down_revision: Union[str, None] = '8532d6f9c999'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add assignment and resolution attribution columns to investigation_cases
    op.add_column('investigation_cases', sa.Column('assigned_to_user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True))
    op.create_index('ix_investigation_cases_assigned_to_user_id', 'investigation_cases', ['assigned_to_user_id'], unique=False)
    
    op.add_column('investigation_cases', sa.Column('resolved_by_user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True))
    op.create_index('ix_investigation_cases_resolved_by_user_id', 'investigation_cases', ['resolved_by_user_id'], unique=False)
    
    op.add_column('investigation_cases', sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True))

    # 2. Create case_notes table
    op.create_table(
        'case_notes',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('case_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('investigation_cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_case_notes_case_id', 'case_notes', ['case_id'], unique=False)
    op.create_index('ix_case_notes_user_id', 'case_notes', ['user_id'], unique=False)

    # 3. Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('case_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('investigation_cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('action', sa.String(), nullable=False),
        sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_audit_logs_case_id', 'audit_logs', ['case_id'], unique=False)
    op.create_index('ix_audit_logs_user_id', 'audit_logs', ['user_id'], unique=False)
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'], unique=False)
    op.create_index('ix_audit_logs_timestamp', 'audit_logs', ['timestamp'], unique=False)


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('case_notes')
    op.drop_column('investigation_cases', 'resolved_at')
    op.drop_column('investigation_cases', 'resolved_by_user_id')
    op.drop_column('investigation_cases', 'assigned_to_user_id')
