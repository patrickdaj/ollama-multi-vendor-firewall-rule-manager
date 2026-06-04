"""Baseline: full initial schema.

Idempotent — each table is only created if it does not already exist,
so this migration is safe to run against a pre-existing database.

Revision ID: 0001
Revises:
Create Date: 2026-06-03
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def _existing_tables() -> set[str]:
    bind = op.get_bind()
    return set(sa.inspect(bind).get_table_names())


def upgrade() -> None:
    existing = _existing_tables()

    # ── device_groups ─────────────────────────────────────────────────────────
    if "device_groups" not in existing:
        op.create_table(
            "device_groups",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("parent_id", sa.BigInteger(), nullable=True),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(
                ["parent_id"], ["device_groups.id"], ondelete="RESTRICT"
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("name"),
        )

    # ── devices ───────────────────────────────────────────────────────────────
    if "devices" not in existing:
        op.create_table(
            "devices",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("vendor", sa.String(50), nullable=False),
            sa.Column("host", sa.String(255), nullable=True),
            sa.Column("port", sa.Integer(), nullable=True),
            sa.Column("verify_ssl", sa.Boolean(), nullable=False, server_default="true"),
            sa.Column("credentials_enc", sa.Text(), nullable=True),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("device_group_id", sa.BigInteger(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(
                ["device_group_id"], ["device_groups.id"], ondelete="SET NULL"
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("name"),
        )

    # ── device_zone_mappings ──────────────────────────────────────────────────
    if "device_zone_mappings" not in existing:
        op.create_table(
            "device_zone_mappings",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column("device_id", sa.BigInteger(), nullable=False),
            sa.Column("logical_zone", sa.String(255), nullable=False),
            sa.Column("vendor_zone", sa.String(255), nullable=False),
            sa.ForeignKeyConstraint(
                ["device_id"], ["devices.id"], ondelete="CASCADE"
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "device_id",
                "logical_zone",
                name="uq_zone_mappings_device_logical",
            ),
        )

    # ── group_policy_rules ────────────────────────────────────────────────────
    if "group_policy_rules" not in existing:
        op.create_table(
            "group_policy_rules",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column("device_group_id", sa.BigInteger(), nullable=False),
            sa.Column("rule_type", sa.String(50), nullable=False, server_default="security"),
            sa.Column("rulebase", sa.String(10), nullable=False, server_default="pre"),
            sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
            sa.Column("base_rule", JSONB(), nullable=False, server_default="{}"),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(
                ["device_group_id"], ["device_groups.id"], ondelete="CASCADE"
            ),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_group_rules_group_rulebase_pos",
            "group_policy_rules",
            ["device_group_id", "rulebase", "position"],
        )

    # ── group_policy_objects ──────────────────────────────────────────────────
    if "group_policy_objects" not in existing:
        op.create_table(
            "group_policy_objects",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column("device_group_id", sa.BigInteger(), nullable=True),
            sa.Column("object_type", sa.String(50), nullable=False),
            sa.Column("object_name", sa.String(255), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("base_data", JSONB(), nullable=False, server_default="{}"),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(
                ["device_group_id"], ["device_groups.id"], ondelete="CASCADE"
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "device_group_id",
                "object_type",
                "object_name",
                name="uq_group_objects_group_type_name",
            ),
        )
        op.create_index(
            "ix_group_objects_type_name",
            "group_policy_objects",
            ["object_type", "object_name"],
        )

    # ── object_translations ───────────────────────────────────────────────────
    if "object_translations" not in existing:
        op.create_table(
            "object_translations",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column("object_type", sa.String(50), nullable=False),
            sa.Column("object_name", sa.String(255), nullable=False),
            sa.Column("target_vendor", sa.String(50), nullable=False),
            sa.Column("translation", JSONB(), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
            sa.Column("ai_reasoning", sa.Text(), nullable=True),
            sa.Column("ai_model", sa.String(100), nullable=True),
            sa.Column("approved_by", sa.String(255), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "object_type",
                "object_name",
                "target_vendor",
                name="uq_object_translations_type_name_vendor",
            ),
        )
        op.create_index(
            "ix_object_translations_vendor_status",
            "object_translations",
            ["target_vendor", "status"],
        )

    # ── rule_translations ─────────────────────────────────────────────────────
    if "rule_translations" not in existing:
        op.create_table(
            "rule_translations",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column("rule_id", sa.BigInteger(), nullable=False),
            sa.Column("target_vendor", sa.String(50), nullable=False),
            sa.Column("translation", JSONB(), nullable=False, server_default="{}"),
            sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
            sa.Column("ai_reasoning", sa.Text(), nullable=True),
            sa.Column("ai_model", sa.String(100), nullable=True),
            sa.Column("approved_by", sa.String(255), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(
                ["rule_id"], ["group_policy_rules.id"], ondelete="CASCADE"
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "rule_id", "target_vendor", name="uq_rule_translations_rule_vendor"
            ),
        )
        op.create_index(
            "ix_rule_translations_vendor_status",
            "rule_translations",
            ["target_vendor", "status"],
        )

    # ── translation_proposals ─────────────────────────────────────────────────
    if "translation_proposals" not in existing:
        op.create_table(
            "translation_proposals",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column("proposal_type", sa.String(10), nullable=False),
            sa.Column("object_type", sa.String(50), nullable=True),
            sa.Column("object_name", sa.String(255), nullable=True),
            sa.Column("rule_id", sa.BigInteger(), nullable=True),
            sa.Column("target_vendor", sa.String(50), nullable=False),
            sa.Column("proposed_translation", JSONB(), nullable=False),
            sa.Column("ai_reasoning", sa.Text(), nullable=True),
            sa.Column("ai_model", sa.String(100), nullable=True),
            sa.Column(
                "triggered_by", sa.String(50), nullable=False, server_default="manual"
            ),
            sa.Column(
                "status", sa.String(20), nullable=False, server_default="pending"
            ),
            sa.Column("reviewed_by", sa.String(255), nullable=True),
            sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(
                ["rule_id"], ["group_policy_rules.id"], ondelete="CASCADE"
            ),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_proposals_vendor_status",
            "translation_proposals",
            ["target_vendor", "status"],
        )
        op.create_index(
            "ix_proposals_type_status",
            "translation_proposals",
            ["proposal_type", "status"],
        )

    # ── snapshots ─────────────────────────────────────────────────────────────
    if "snapshots" not in existing:
        op.create_table(
            "snapshots",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column("device_id", sa.BigInteger(), nullable=False),
            sa.Column(
                "status", sa.String(20), nullable=False, server_default="in_progress"
            ),
            sa.Column(
                "triggered_by", sa.String(50), nullable=False, server_default="manual"
            ),
            sa.Column("object_count", sa.BigInteger(), nullable=True),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_snapshots_device_created",
            "snapshots",
            ["device_id", "created_at"],
        )

    # ── policy_objects ────────────────────────────────────────────────────────
    if "policy_objects" not in existing:
        op.create_table(
            "policy_objects",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column("snapshot_id", sa.BigInteger(), nullable=False),
            sa.Column("device_id", sa.BigInteger(), nullable=False),
            sa.Column("object_type", sa.String(50), nullable=False),
            sa.Column("object_name", sa.String(255), nullable=False),
            sa.Column("vendor", sa.String(50), nullable=False),
            sa.Column("data", JSONB(), nullable=False),
            sa.Column("content_hash", sa.String(64), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
            sa.ForeignKeyConstraint(["snapshot_id"], ["snapshots.id"]),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "snapshot_id",
                "object_type",
                "object_name",
                name="uq_policy_objects_snapshot_type_name",
            ),
        )
        op.create_index(
            "ix_policy_objects_snapshot_type",
            "policy_objects",
            ["snapshot_id", "object_type"],
        )
        op.create_index(
            "ix_policy_objects_device_type_name",
            "policy_objects",
            ["device_id", "object_type", "object_name"],
        )
        op.create_index(
            "ix_policy_objects_hash",
            "policy_objects",
            ["content_hash"],
        )

    # ── policy_diffs ──────────────────────────────────────────────────────────
    if "policy_diffs" not in existing:
        op.create_table(
            "policy_diffs",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column("device_id", sa.BigInteger(), nullable=False),
            sa.Column("from_snapshot_id", sa.BigInteger(), nullable=False),
            sa.Column("to_snapshot_id", sa.BigInteger(), nullable=False),
            sa.Column("object_type", sa.String(50), nullable=False),
            sa.Column("object_name", sa.String(255), nullable=False),
            sa.Column("change_type", sa.String(20), nullable=False),
            sa.Column("before", JSONB(), nullable=True),
            sa.Column("after", JSONB(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(["device_id"], ["devices.id"]),
            sa.ForeignKeyConstraint(["from_snapshot_id"], ["snapshots.id"]),
            sa.ForeignKeyConstraint(["to_snapshot_id"], ["snapshots.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_policy_diffs_device_to_snapshot",
            "policy_diffs",
            ["device_id", "to_snapshot_id"],
        )


def downgrade() -> None:
    # Drop in reverse dependency order.
    for table in [
        "policy_diffs",
        "policy_objects",
        "snapshots",
        "translation_proposals",
        "rule_translations",
        "object_translations",
        "group_policy_objects",
        "group_policy_rules",
        "device_zone_mappings",
        "devices",
        "device_groups",
    ]:
        op.drop_table(table)
