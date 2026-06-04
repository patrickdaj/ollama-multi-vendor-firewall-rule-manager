"""Add push_jobs and push_job_items tables for push engine.

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-03
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())

    if "push_jobs" not in existing:
        op.create_table(
            "push_jobs",
            sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
            sa.Column("device_id", sa.BigInteger, sa.ForeignKey("devices.id"), nullable=False),
            sa.Column("group_id", sa.BigInteger, sa.ForeignKey("device_groups.id"), nullable=False),
            sa.Column("triggered_by", sa.String(50), nullable=False, server_default="manual"),
            sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
            sa.Column("dry_run", sa.Boolean, nullable=False, server_default="true"),
            sa.Column("started_at", sa.DateTime(timezone=True)),
            sa.Column("completed_at", sa.DateTime(timezone=True)),
            sa.Column("pushed_rules", sa.Integer, nullable=False, server_default="0"),
            sa.Column("pushed_objects", sa.Integer, nullable=False, server_default="0"),
            sa.Column("error_summary", sa.Text),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
            ),
        )
        op.create_index("ix_push_jobs_device_created", "push_jobs", ["device_id", "created_at"])

    if "push_job_items" not in existing:
        op.create_table(
            "push_job_items",
            sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
            sa.Column("job_id", sa.BigInteger, sa.ForeignKey("push_jobs.id", ondelete="CASCADE"), nullable=False),
            sa.Column("item_type", sa.String(10), nullable=False),
            sa.Column("object_type", sa.String(50), nullable=False),
            sa.Column("item_name", sa.String(255), nullable=False),
            sa.Column("action", sa.String(20), nullable=False),
            sa.Column("vendor_payload", JSONB, nullable=False, server_default="{}"),
            sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
            sa.Column("error", sa.Text),
            sa.Column("sequence", sa.Integer, nullable=False, server_default="0"),
        )
        op.create_index("ix_push_job_items_job_seq", "push_job_items", ["job_id", "sequence"])


def downgrade() -> None:
    op.drop_table("push_job_items")
    op.drop_table("push_jobs")
