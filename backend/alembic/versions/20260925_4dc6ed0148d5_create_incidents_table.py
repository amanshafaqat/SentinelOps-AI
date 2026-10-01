"""create_incidents_and_audit_tables

Revision ID: 4dc6ed0148d5
Revises: 3bc5dc9037c4
Create Date: 2026-09-25 10:40:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '4dc6ed0148d5'
down_revision: Union[str, None] = '3bc5dc9037c4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    # 1. Create incidents table
    if 'incidents' not in tables:
        op.create_table(
            'incidents',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('title', sa.String(length=255), nullable=False),
            sa.Column('description', sa.Text(), nullable=False),
            sa.Column('severity', sa.String(length=32), nullable=False, server_default='medium'),
            sa.Column('status', sa.String(length=32), nullable=False, server_default='new'),
            sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
            sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
            sa.Column('affected_users', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
            sa.Column('affected_ips', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
            sa.Column('affected_hostnames', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
            sa.Column('correlation_reasons', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
            sa.Column('correlation_metadata', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_incidents_id'), 'incidents', ['id'], unique=False)
        op.create_index(op.f('ix_incidents_severity'), 'incidents', ['severity'], unique=False)
        op.create_index(op.f('ix_incidents_status'), 'incidents', ['status'], unique=False)
        op.create_index(op.f('ix_incidents_first_seen'), 'incidents', ['first_seen'], unique=False)
        op.create_index(op.f('ix_incidents_last_seen'), 'incidents', ['last_seen'], unique=False)
        op.create_index(op.f('ix_incidents_created_at'), 'incidents', ['created_at'], unique=False)
        op.create_index(op.f('ix_incidents_updated_at'), 'incidents', ['updated_at'], unique=False)
        op.create_index('ix_incidents_severity_status', 'incidents', ['severity', 'status'], unique=False)

    # 2. Create incident_audit_logs table
    if 'incident_audit_logs' not in tables:
        op.create_table(
            'incident_audit_logs',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('incident_id', sa.String(length=36), nullable=False),
            sa.Column('action', sa.String(length=64), nullable=False),
            sa.Column('previous_value', sa.String(length=255), nullable=True),
            sa.Column('new_value', sa.String(length=255), nullable=True),
            sa.Column('notes', sa.Text(), nullable=True),
            sa.Column('actor', sa.String(length=128), nullable=False, server_default='system'),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_incident_audit_logs_id'), 'incident_audit_logs', ['id'], unique=False)
        op.create_index(op.f('ix_incident_audit_logs_incident_id'), 'incident_audit_logs', ['incident_id'], unique=False)
        op.create_index(op.f('ix_incident_audit_logs_created_at'), 'incident_audit_logs', ['created_at'], unique=False)

    # 3. Add foreign key from alerts.incident_id -> incidents.id (on non-sqlite dialects)
    if conn.dialect.name != 'sqlite':
        op.create_foreign_key(
            'fk_alerts_incident_id_incidents',
            'alerts',
            'incidents',
            ['incident_id'],
            ['id'],
            ondelete='SET NULL'
        )


def downgrade() -> None:
    op.drop_constraint('fk_alerts_incident_id_incidents', 'alerts', type_='foreignkey')
    op.drop_index(op.f('ix_incident_audit_logs_created_at'), table_name='incident_audit_logs')
    op.drop_index(op.f('ix_incident_audit_logs_incident_id'), table_name='incident_audit_logs')
    op.drop_index(op.f('ix_incident_audit_logs_id'), table_name='incident_audit_logs')
    op.drop_table('incident_audit_logs')

    op.drop_index('ix_incidents_severity_status', table_name='incidents')
    op.drop_index(op.f('ix_incidents_updated_at'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_created_at'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_last_seen'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_first_seen'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_status'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_severity'), table_name='incidents')
    op.drop_index(op.f('ix_incidents_id'), table_name='incidents')
    op.drop_table('incidents')
