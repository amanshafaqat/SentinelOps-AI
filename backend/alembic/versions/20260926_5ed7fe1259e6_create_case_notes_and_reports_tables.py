"""create_case_notes_and_reports_tables

Revision ID: 5ed7fe1259e6
Revises: 4dc6ed0148d5
Create Date: 2026-09-26 12:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '5ed7fe1259e6'
down_revision: Union[str, None] = '4dc6ed0148d5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create incident_ai_analyses table (if not exists)
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    if 'incident_ai_analyses' not in tables:
        op.create_table(
            'incident_ai_analyses',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('incident_id', sa.String(length=36), nullable=False),
            sa.Column('analysis_type', sa.String(length=64), nullable=False),
            sa.Column('query', sa.Text(), nullable=True),
            sa.Column('model', sa.String(length=128), nullable=False),
            sa.Column('summary', sa.Text(), nullable=False),
            sa.Column('observed_facts', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
            sa.Column('potential_explanations', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
            sa.Column('evidence_references', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
            sa.Column('missing_information', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
            sa.Column('recommended_next_steps', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
            sa.Column('uncertainty_assessment', sa.Text(), nullable=False, server_default=''),
            sa.Column('evidence_truncated', sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column('actor', sa.String(length=128), nullable=False, server_default='soc_analyst'),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_incident_ai_analyses_id'), 'incident_ai_analyses', ['id'], unique=False)
        op.create_index(op.f('ix_incident_ai_analyses_incident_id'), 'incident_ai_analyses', ['incident_id'], unique=False)
        op.create_index(op.f('ix_incident_ai_analyses_created_at'), 'incident_ai_analyses', ['created_at'], unique=False)

    # 2. Create case_notes table
    if 'case_notes' not in tables:
        op.create_table(
            'case_notes',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('incident_id', sa.String(length=36), nullable=False),
            sa.Column('author', sa.String(length=128), nullable=False, server_default='soc_analyst'),
            sa.Column('content', sa.Text(), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_case_notes_id'), 'case_notes', ['id'], unique=False)
        op.create_index(op.f('ix_case_notes_incident_id'), 'case_notes', ['incident_id'], unique=False)
        op.create_index(op.f('ix_case_notes_created_at'), 'case_notes', ['created_at'], unique=False)

    # 3. Create investigation_reports table
    if 'investigation_reports' not in tables:
        op.create_table(
            'investigation_reports',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('incident_id', sa.String(length=36), nullable=False),
            sa.Column('title', sa.String(length=255), nullable=False),
            sa.Column('report_type', sa.String(length=64), nullable=False, server_default='investigation_summary'),
            sa.Column('generated_by', sa.String(length=128), nullable=False, server_default='soc_analyst'),
            sa.Column('summary', sa.Text(), nullable=False),
            sa.Column('content', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
            sa.Column('rendered_html', sa.Text(), nullable=False),
            sa.Column('metadata_info', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_investigation_reports_id'), 'investigation_reports', ['id'], unique=False)
        op.create_index(op.f('ix_investigation_reports_incident_id'), 'investigation_reports', ['incident_id'], unique=False)
        op.create_index(op.f('ix_investigation_reports_created_at'), 'investigation_reports', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_investigation_reports_created_at'), table_name='investigation_reports')
    op.drop_index(op.f('ix_investigation_reports_incident_id'), table_name='investigation_reports')
    op.drop_index(op.f('ix_investigation_reports_id'), table_name='investigation_reports')
    op.drop_table('investigation_reports')

    op.drop_index(op.f('ix_case_notes_created_at'), table_name='case_notes')
    op.drop_index(op.f('ix_case_notes_incident_id'), table_name='case_notes')
    op.drop_index(op.f('ix_case_notes_id'), table_name='case_notes')
    op.drop_table('case_notes')

    op.drop_index(op.f('ix_incident_ai_analyses_created_at'), table_name='incident_ai_analyses')
    op.drop_index(op.f('ix_incident_ai_analyses_incident_id'), table_name='incident_ai_analyses')
    op.drop_index(op.f('ix_incident_ai_analyses_id'), table_name='incident_ai_analyses')
    op.drop_table('incident_ai_analyses')
