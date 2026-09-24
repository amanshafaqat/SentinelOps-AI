"""create_alerts_and_evidence_tables

Revision ID: 3bc5dc9037c4
Revises: 2ac4cb8026b3
Create Date: 2026-09-24 18:35:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '3bc5dc9037c4'
down_revision: Union[str, None] = '2ac4cb8026b3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create alerts table
    op.create_table(
        'alerts',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('rule_name', sa.String(length=128), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='new'),
        sa.Column('dedup_key', sa.String(length=255), nullable=False),
        sa.Column('affected_user', sa.String(length=128), nullable=True),
        sa.Column('affected_ip', sa.String(length=45), nullable=True),
        sa.Column('affected_hostname', sa.String(length=128), nullable=True),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('incident_id', sa.String(length=36), nullable=True),
        sa.Column('alert_metadata', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_alerts_id'), 'alerts', ['id'], unique=False)
    op.create_index(op.f('ix_alerts_rule_id'), 'alerts', ['rule_id'], unique=False)
    op.create_index(op.f('ix_alerts_severity'), 'alerts', ['severity'], unique=False)
    op.create_index(op.f('ix_alerts_status'), 'alerts', ['status'], unique=False)
    op.create_index(op.f('ix_alerts_dedup_key'), 'alerts', ['dedup_key'], unique=True)
    op.create_index(op.f('ix_alerts_affected_user'), 'alerts', ['affected_user'], unique=False)
    op.create_index(op.f('ix_alerts_affected_ip'), 'alerts', ['affected_ip'], unique=False)
    op.create_index(op.f('ix_alerts_affected_hostname'), 'alerts', ['affected_hostname'], unique=False)
    op.create_index(op.f('ix_alerts_detected_at'), 'alerts', ['detected_at'], unique=False)
    op.create_index(op.f('ix_alerts_created_at'), 'alerts', ['created_at'], unique=False)
    op.create_index(op.f('ix_alerts_incident_id'), 'alerts', ['incident_id'], unique=False)
    op.create_index('ix_alerts_severity_status', 'alerts', ['severity', 'status'], unique=False)
    op.create_index('ix_alerts_rule_detected', 'alerts', ['rule_id', 'detected_at'], unique=False)
    op.create_index('ix_alerts_user_detected', 'alerts', ['affected_user', 'detected_at'], unique=False)

    # 2. Create alert_evidence table
    op.create_table(
        'alert_evidence',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('alert_id', sa.String(length=36), nullable=False),
        sa.Column('event_id', sa.String(length=36), nullable=False),
        sa.Column('evidence_role', sa.String(length=64), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['event_id'], ['security_events.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('alert_id', 'event_id', name='uq_alert_event_evidence')
    )
    op.create_index(op.f('ix_alert_evidence_id'), 'alert_evidence', ['id'], unique=False)
    op.create_index(op.f('ix_alert_evidence_alert_id'), 'alert_evidence', ['alert_id'], unique=False)
    op.create_index(op.f('ix_alert_evidence_event_id'), 'alert_evidence', ['event_id'], unique=False)
    op.create_index('ix_alert_evidence_alert_event', 'alert_evidence', ['alert_id', 'event_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_alert_evidence_alert_event', table_name='alert_evidence')
    op.drop_index(op.f('ix_alert_evidence_event_id'), table_name='alert_evidence')
    op.drop_index(op.f('ix_alert_evidence_alert_id'), table_name='alert_evidence')
    op.drop_index(op.f('ix_alert_evidence_id'), table_name='alert_evidence')
    op.drop_table('alert_evidence')

    op.drop_index('ix_alerts_user_detected', table_name='alerts')
    op.drop_index('ix_alerts_rule_detected', table_name='alerts')
    op.drop_index('ix_alerts_severity_status', table_name='alerts')
    op.drop_index(op.f('ix_alerts_incident_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_created_at'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_detected_at'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_affected_hostname'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_affected_ip'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_affected_user'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_dedup_key'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_status'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_severity'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_rule_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_id'), table_name='alerts')
    op.drop_table('alerts')
