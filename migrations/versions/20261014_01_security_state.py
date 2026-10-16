"""Create durable approval and audit state."""

import sqlalchemy as sa
from alembic import op

revision = "20261014_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "approval_records",
        sa.Column("approval_id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(64), nullable=False, index=True),
        sa.Column("requester_id", sa.String(64), nullable=False),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("arguments_digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.String(64), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.String(36), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("request_id", sa.String(64), nullable=False, index=True),
        sa.Column("user_id", sa.String(64), nullable=False, index=True),
        sa.Column("workspace_id", sa.String(64), nullable=False, index=True),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("tool", sa.String(64), nullable=True),
        sa.Column("resource", sa.String(256), nullable=True),
        sa.Column("classification", sa.String(32), nullable=True),
        sa.Column("policy_decision", sa.String(32), nullable=True),
        sa.Column("policy_id", sa.String(64), nullable=True),
        sa.Column("approval_id", sa.String(36), nullable=True),
        sa.Column("result", sa.String(64), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False, index=True),
    )


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("approval_records")
