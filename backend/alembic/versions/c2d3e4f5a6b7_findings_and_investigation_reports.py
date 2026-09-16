"""evidence-backed findings and persisted investigation reports

Revision ID: c2d3e4f5a6b7
Revises: b7c1e2d3f4a5
Create Date: 2026-09-17

- agent_reasoning_steps.evidence_ids: evidence referenced by each reasoning step
- agent_findings + agent_finding_evidence: agent conclusions linked to evidence items
- investigation_reports: canonical, versioned report (single source for API, UI, PDF)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = 'c2d3e4f5a6b7'
down_revision: Union[str, None] = 'b7c1e2d3f4a5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'agent_reasoning_steps',
        sa.Column('evidence_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
    )
    op.alter_column('agent_reasoning_steps', 'evidence_ids', server_default=None)

    op.create_table(
        'agent_findings',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('case_id', sa.UUID(), nullable=False),
        sa.Column('execution_id', sa.UUID(), nullable=False),
        sa.Column('agent_name', sa.String(), nullable=False),
        sa.Column('finding', sa.Text(), nullable=False),
        sa.Column('kind', sa.String(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('reasoning_summary', sa.Text(), nullable=True),
        sa.Column('mitre_techniques', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['investigation_cases.id']),
        sa.ForeignKeyConstraint(['execution_id'], ['agent_executions.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_agent_findings_case_id'), 'agent_findings', ['case_id'], unique=False)
    op.create_index(op.f('ix_agent_findings_execution_id'), 'agent_findings', ['execution_id'], unique=False)
    op.create_index(op.f('ix_agent_findings_agent_name'), 'agent_findings', ['agent_name'], unique=False)

    op.create_table(
        'agent_finding_evidence',
        sa.Column('finding_id', sa.UUID(), nullable=False),
        sa.Column('evidence_item_id', sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(['finding_id'], ['agent_findings.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['evidence_item_id'], ['evidence_items.id']),
        sa.PrimaryKeyConstraint('finding_id', 'evidence_item_id'),
    )
    op.create_index(op.f('ix_agent_finding_evidence_evidence_item_id'), 'agent_finding_evidence', ['evidence_item_id'], unique=False)

    op.create_table(
        'investigation_reports',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('case_id', sa.UUID(), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('is_current', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('generated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('soc_lead_execution_id', sa.UUID(), nullable=True),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=True),
        sa.Column('executive_summary', sa.Text(), nullable=True),
        sa.Column('finding_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('recommendations', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('mitre_techniques', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('timeline', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('timeline_source', sa.String(), nullable=False),
        sa.Column('evidence_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('agent_runs', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['investigation_cases.id']),
        sa.ForeignKeyConstraint(['soc_lead_execution_id'], ['agent_executions.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_investigation_reports_case_id'), 'investigation_reports', ['case_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_investigation_reports_case_id'), table_name='investigation_reports')
    op.drop_table('investigation_reports')
    op.drop_index(op.f('ix_agent_finding_evidence_evidence_item_id'), table_name='agent_finding_evidence')
    op.drop_table('agent_finding_evidence')
    op.drop_index(op.f('ix_agent_findings_agent_name'), table_name='agent_findings')
    op.drop_index(op.f('ix_agent_findings_execution_id'), table_name='agent_findings')
    op.drop_index(op.f('ix_agent_findings_case_id'), table_name='agent_findings')
    op.drop_table('agent_findings')
    op.drop_column('agent_reasoning_steps', 'evidence_ids')
