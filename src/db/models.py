"""SQLAlchemy ORM models — PostgreSQL source of truth.

Two categories of data live here:

  OBSERVED STATE  — what was ingested from devices
    Snapshot, PolicyObject, PolicyDiff

  DESIRED STATE   — the SOT managed by this platform
    DeviceGroup, GroupPolicyRule, GroupPolicyObject,
    DeviceZoneMapping, ObjectTranslation, RuleTranslation, TranslationProposal

  CONFIGURATION
    SystemSetting — operator-configurable key/value pairs (default credentials, etc.)

Version history is preserved indefinitely for observed state. Desired state is
mutable — changes are the point.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# ── Configuration ─────────────────────────────────────────────────────────────


class SystemSetting(Base):
    """Operator-configurable key/value pairs stored in the database.

    Keys are plain strings (e.g. "default_username", "default_verify_ssl").
    Values are JSON-serialized strings so booleans, numbers, and strings all fit
    in one column without schema changes.

    Intended for settings that operators change at runtime via the Settings page,
    not for secrets that belong in environment variables.
    """

    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="null")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


# ── Desired state: device group hierarchy ─────────────────────────────────────


class DeviceGroup(Base):
    """Hierarchical device group — mirrors Panorama's Device Group concept.

    Groups form a tree (parent_id=None → root). Policy rules and shared objects
    defined at a group level are inherited by all descendant groups and devices.
    A device belongs to exactly one group (or none, for unmanaged devices).

    Rulebase evaluation order for any device in group G:
      pre-rules(root) → pre-rules(…ancestors…) → pre-rules(G)
        → device-local rules
      post-rules(G) → post-rules(…ancestors…) → post-rules(root)
    """

    __tablename__ = "device_groups"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("device_groups.id", ondelete="RESTRICT"), nullable=True
    )
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    parent: Mapped[DeviceGroup | None] = relationship(
        "DeviceGroup", remote_side="DeviceGroup.id", back_populates="children"
    )
    children: Mapped[list[DeviceGroup]] = relationship(
        "DeviceGroup", back_populates="parent"
    )
    devices: Mapped[list[Device]] = relationship(back_populates="device_group")
    rules: Mapped[list[GroupPolicyRule]] = relationship(
        back_populates="device_group", order_by="GroupPolicyRule.position"
    )
    objects: Mapped[list[GroupPolicyObject]] = relationship(back_populates="device_group")


# ── Desired state: devices ─────────────────────────────────────────────────────


class Device(Base):
    """Registered firewall device.

    Connection metadata lives here. Credentials are stored Fernet-encrypted
    so they survive container restarts without being in plaintext env vars.
    The ENCRYPTION_KEY env var is the only secret needed to decrypt them.

    device_group_id is nullable — unassigned devices are still managed for
    ingest/RAG but are not subject to group policy push.
    """

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    vendor: Mapped[str] = mapped_column(String(50), nullable=False)
    host: Mapped[str | None] = mapped_column(String(255))
    port: Mapped[int | None] = mapped_column(Integer)
    verify_ssl: Mapped[bool] = mapped_column(Boolean, default=True)
    # Fernet-encrypted JSON: {username, password, api_key, ...}
    credentials_enc: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    # Group membership — nullable, assigned via PATCH /devices/{name}
    device_group_id: Mapped[int | None] = mapped_column(
        ForeignKey("device_groups.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    device_group: Mapped[DeviceGroup | None] = relationship(back_populates="devices")
    snapshots: Mapped[list[Snapshot]] = relationship(
        back_populates="device", order_by="Snapshot.created_at"
    )
    zone_mappings: Mapped[list[DeviceZoneMapping]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )


class DeviceZoneMapping(Base):
    """Maps logical zone names (used in group policy) to device-specific zone names.

    Logical zones are defined at the group policy level so rules can be written
    vendor-neutrally (e.g. src_zones: ["internal"]).  Each device maps its
    physical zones to those logical names during onboarding.

    Example:
      PAN-OS fw01:  internal → "trust",   external → "untrust"
      FortiGate fg01: internal → "LAN",   external → "WAN"
      ASA asa01:    internal → "inside",  external → "outside"
    """

    __tablename__ = "device_zone_mappings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    logical_zone: Mapped[str] = mapped_column(String(255), nullable=False)
    vendor_zone: Mapped[str] = mapped_column(String(255), nullable=False)

    device: Mapped[Device] = relationship(back_populates="zone_mappings")

    __table_args__ = (
        UniqueConstraint("device_id", "logical_zone", name="uq_zone_mappings_device_logical"),
    )


# ── Desired state: group-level policy rules ───────────────────────────────────


class GroupPolicyRule(Base):
    """A policy rule defined at the device group level (desired state).

    Rules are vendor-agnostic — they use logical zone names and normalized
    object references.  Vendor-specific rendering is handled by RuleTranslation
    and ObjectTranslation at push time.

    rulebase:
      "pre"   — enforced before device-local rules (inherited from parent groups first)
      "post"  — enforced after device-local rules (parent groups last)
      "local" — device-local override rules (rarely used at group level)

    rule_type: security | nat | decryption | dos | auth
    """

    __tablename__ = "group_policy_rules"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    device_group_id: Mapped[int] = mapped_column(
        ForeignKey("device_groups.id", ondelete="CASCADE"), nullable=False
    )
    rule_type: Mapped[str] = mapped_column(String(50), nullable=False, default="security")
    rulebase: Mapped[str] = mapped_column(String(10), nullable=False, default="pre")
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Vendor-agnostic rule definition matching FirewallRule / NATRule / etc. model fields
    base_rule: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    device_group: Mapped[DeviceGroup] = relationship(back_populates="rules")
    translations: Mapped[list[RuleTranslation]] = relationship(
        back_populates="rule", cascade="all, delete-orphan"
    )
    proposals: Mapped[list[TranslationProposal]] = relationship(
        back_populates="rule",
        primaryjoin="and_(TranslationProposal.rule_id == GroupPolicyRule.id, "
                    "TranslationProposal.proposal_type == 'rule')",
        cascade="all, delete-orphan",
        foreign_keys="TranslationProposal.rule_id",
    )

    __table_args__ = (
        Index("ix_group_rules_group_rulebase_pos", "device_group_id", "rulebase", "position"),
    )


# ── Desired state: group-level shared objects ─────────────────────────────────


class GroupPolicyObject(Base):
    """A policy object defined at the device group level (desired state).

    device_group_id=NULL means the object is at the shared/root level and
    available to every group and device.

    Object definitions are vendor-agnostic. Vendor-specific representations
    are stored in ObjectTranslation.

    object_type: address_object | service_object | service_group | application |
                 app_group | url_category | security_profile | decryption_profile |
                 edl | zone
    """

    __tablename__ = "group_policy_objects"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # NULL = shared root scope
    device_group_id: Mapped[int | None] = mapped_column(
        ForeignKey("device_groups.id", ondelete="CASCADE"), nullable=True
    )
    object_type: Mapped[str] = mapped_column(String(50), nullable=False)
    object_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Vendor-agnostic object data matching the appropriate Pydantic model
    base_data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    device_group: Mapped[DeviceGroup | None] = relationship(back_populates="objects")

    __table_args__ = (
        UniqueConstraint(
            "device_group_id", "object_type", "object_name",
            name="uq_group_objects_group_type_name",
        ),
        Index("ix_group_objects_type_name", "object_type", "object_name"),
    )


# ── Desired state: vendor translations ────────────────────────────────────────


class ObjectTranslation(Base):
    """Approved vendor-specific representation of a named policy object.

    Reusable across all rules that reference the same object name.  When the
    push engine encounters an object referenced by a rule, it looks up the
    ObjectTranslation for the target vendor first; only if none exists does it
    fall back to the vendor-neutral base_data.

    Example — application object "ssl" targeting cisco_asa:
      translation = {"type": "service", "protocol": "tcp", "port": "443"}

    Example — application object "ssl" targeting fortinet:
      translation = {"type": "application_signature", "app_name": "SSL"}

    status: approved | pending | rejected
    """

    __tablename__ = "object_translations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    object_type: Mapped[str] = mapped_column(String(50), nullable=False)
    object_name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_vendor: Mapped[str] = mapped_column(String(50), nullable=False)
    translation: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    ai_reasoning: Mapped[str | None] = mapped_column(Text)
    ai_model: Mapped[str | None] = mapped_column(String(100))
    approved_by: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "object_type", "object_name", "target_vendor",
            name="uq_object_translations_type_name_vendor",
        ),
        Index("ix_object_translations_vendor_status", "target_vendor", "status"),
    )


class RuleTranslation(Base):
    """Approved vendor-specific override for a specific GroupPolicyRule.

    Applied on top of the vendor-neutral base_rule at push time. Only fields
    that differ from the base need to be present — the push engine merges
    base_rule + translation for the target vendor.

    Use when a rule needs vendor-specific behavior beyond what ObjectTranslation
    can provide — e.g. a rule that should use a different action on ASA vs PAN-OS,
    or a rule that adds vendor-specific profile references.

    status: approved | pending | rejected
    """

    __tablename__ = "rule_translations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    rule_id: Mapped[int] = mapped_column(
        ForeignKey("group_policy_rules.id", ondelete="CASCADE"), nullable=False
    )
    target_vendor: Mapped[str] = mapped_column(String(50), nullable=False)
    # Partial override — only fields that differ from base_rule need to be present
    translation: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    ai_reasoning: Mapped[str | None] = mapped_column(Text)
    ai_model: Mapped[str | None] = mapped_column(String(100))
    approved_by: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    rule: Mapped[GroupPolicyRule] = relationship(back_populates="translations")

    __table_args__ = (
        UniqueConstraint("rule_id", "target_vendor", name="uq_rule_translations_rule_vendor"),
        Index("ix_rule_translations_vendor_status", "target_vendor", "status"),
    )


class TranslationProposal(Base):
    """AI-generated translation proposal awaiting human review.

    Created automatically when a new vendor is added to a device group and
    gap detection finds rules or objects without an approved translation for
    that vendor.

    proposal_type: "rule" | "object"
    status: pending | approved | rejected | modified

    On approval: creates/updates the corresponding ObjectTranslation or
    RuleTranslation record with status="approved".

    On modified: the human edits proposed_translation before approving —
    the edited version is stored and the ai_reasoning is preserved for audit.
    """

    __tablename__ = "translation_proposals"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    proposal_type: Mapped[str] = mapped_column(String(10), nullable=False)

    # For object proposals
    object_type: Mapped[str | None] = mapped_column(String(50))
    object_name: Mapped[str | None] = mapped_column(String(255))

    # For rule proposals
    rule_id: Mapped[int | None] = mapped_column(
        ForeignKey("group_policy_rules.id", ondelete="CASCADE"), nullable=True
    )

    target_vendor: Mapped[str] = mapped_column(String(50), nullable=False)
    proposed_translation: Mapped[dict] = mapped_column(JSONB, nullable=False)
    ai_reasoning: Mapped[str | None] = mapped_column(Text)
    ai_model: Mapped[str | None] = mapped_column(String(100))
    # device_onboard | manual | batch
    triggered_by: Mapped[str] = mapped_column(String(50), default="manual")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    reviewed_by: Mapped[str | None] = mapped_column(String(255))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    rule: Mapped[GroupPolicyRule | None] = relationship(
        back_populates="proposals",
        foreign_keys=[rule_id],
    )

    __table_args__ = (
        Index("ix_proposals_vendor_status", "target_vendor", "status"),
        Index("ix_proposals_type_status", "proposal_type", "status"),
    )


# ── Push jobs ─────────────────────────────────────────────────────────────────


class PushJob(Base):
    """Tracks a push of group policy to a specific device.

    Status flow: pending → running → complete | failed | partial | rolled_back
    dry_run=True means the job was compiled and diffed but no changes were sent.
    """

    __tablename__ = "push_jobs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), nullable=False)
    group_id: Mapped[int] = mapped_column(ForeignKey("device_groups.id"), nullable=False)
    # manual | scheduled | drift-resolve
    triggered_by: Mapped[str] = mapped_column(String(50), default="manual")
    # pending | running | complete | failed | partial | rolled_back
    status: Mapped[str] = mapped_column(String(20), default="pending")
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pushed_rules: Mapped[int] = mapped_column(Integer, default=0)
    pushed_objects: Mapped[int] = mapped_column(Integer, default=0)
    error_summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    items: Mapped[list[PushJobItem]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_push_jobs_device_created", "device_id", "created_at"),
    )


class PushJobItem(Base):
    """One rule or object within a push job and its deployment outcome."""

    __tablename__ = "push_job_items"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    job_id: Mapped[int] = mapped_column(
        ForeignKey("push_jobs.id", ondelete="CASCADE"), nullable=False
    )
    # rule | object
    item_type: Mapped[str] = mapped_column(String(10), nullable=False)
    object_type: Mapped[str] = mapped_column(String(50), nullable=False)
    item_name: Mapped[str] = mapped_column(String(255), nullable=False)
    # create | update | delete | no-change
    action: Mapped[str] = mapped_column(String(20), nullable=False)
    # vendor-specific payload that was (or would be) sent
    vendor_payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # pending | success | failed | skipped
    status: Mapped[str] = mapped_column(String(20), default="pending")
    error: Mapped[str | None] = mapped_column(Text)
    sequence: Mapped[int] = mapped_column(Integer, default=0)

    job: Mapped[PushJob] = relationship(back_populates="items")

    __table_args__ = (
        Index("ix_push_job_items_job_seq", "job_id", "sequence"),
    )


# ── Observed state: ingest snapshots ─────────────────────────────────────────


class Snapshot(Base):
    """One complete ingestion of a device's policy state."""

    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), nullable=False)
    # in_progress → complete | failed
    status: Mapped[str] = mapped_column(String(20), default="in_progress")
    # manual | scheduled | api | bootstrap
    triggered_by: Mapped[str] = mapped_column(String(50), default="manual")
    object_count: Mapped[int | None] = mapped_column(BigInteger)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    device: Mapped[Device] = relationship(back_populates="snapshots")
    objects: Mapped[list[PolicyObject]] = relationship(back_populates="snapshot")

    __table_args__ = (
        Index("ix_snapshots_device_created", "device_id", "created_at"),
    )


class PolicyObject(Base):
    """A single policy object (rule, address, NAT entry, EDL, …) within a snapshot.

    Observed state only — written on ingest, never edited directly.
    To modify policy, edit GroupPolicyObject or GroupPolicyRule (desired state).

    The full object is stored as JSONB so every field survives regardless of
    which Phase the parser is at. content_hash enables O(1) change detection
    between snapshots without deserialising the data.
    """

    __tablename__ = "policy_objects"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"), nullable=False)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), nullable=False)
    # security_rule | nat_rule | address_object | service_object | application |
    # app_group | url_category | security_profile | decryption_rule |
    # decryption_profile | dos_policy | auth_policy | edl | zone
    object_type: Mapped[str] = mapped_column(String(50), nullable=False)
    object_name: Mapped[str] = mapped_column(String(255), nullable=False)
    vendor: Mapped[str] = mapped_column(String(50), nullable=False)
    data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    # SHA-256 of canonical JSON — used for diff detection
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    snapshot: Mapped[Snapshot] = relationship(back_populates="objects")

    __table_args__ = (
        UniqueConstraint(
            "snapshot_id", "object_type", "object_name",
            name="uq_policy_objects_snapshot_type_name",
        ),
        Index("ix_policy_objects_snapshot_type", "snapshot_id", "object_type"),
        Index("ix_policy_objects_device_type_name", "device_id", "object_type", "object_name"),
        Index("ix_policy_objects_hash", "content_hash"),
    )


class PolicyDiff(Base):
    """Change record between two consecutive snapshots of the same device.

    Computed automatically when a new snapshot completes. Enables answering
    "what changed since the last sync?" without full deserialization.
    """

    __tablename__ = "policy_diffs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), nullable=False)
    from_snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"), nullable=False)
    to_snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"), nullable=False)
    object_type: Mapped[str] = mapped_column(String(50), nullable=False)
    object_name: Mapped[str] = mapped_column(String(255), nullable=False)
    # added | removed | modified
    change_type: Mapped[str] = mapped_column(String(20), nullable=False)
    before: Mapped[dict | None] = mapped_column(JSONB)
    after: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        Index("ix_policy_diffs_device_to_snapshot", "device_id", "to_snapshot_id"),
    )
