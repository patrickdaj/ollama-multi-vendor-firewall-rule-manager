"""Translation management — object translations, rule translations, and AI proposals."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select

from src.ai.translate_policy_fast import fast_translate_object
from src.ai.translation import generate_object_translation, generate_rule_translation
from src.config import settings
from src.db.models import (
    GroupPolicyObject,
    GroupPolicyRule,
    ObjectTranslation,
    RuleTranslation,
    TranslationProposal,
)
from src.db.session import AsyncSessionLocal

router = APIRouter(tags=["translations"])
log = logging.getLogger(__name__)


# ── Schemas ───────────────────────────────────────────────────────────────────


class ObjectTranslationIn(BaseModel):
    object_type: str
    object_name: str
    target_vendor: str
    translation: dict[str, Any]
    ai_reasoning: str | None = None
    ai_model: str | None = None


class ObjectTranslationOut(BaseModel):
    id: int
    object_type: str
    object_name: str
    target_vendor: str
    translation: dict[str, Any]
    status: str
    ai_reasoning: str | None
    ai_model: str | None
    approved_by: str | None
    created_at: datetime
    updated_at: datetime | None


class RuleTranslationIn(BaseModel):
    rule_id: int
    target_vendor: str
    translation: dict[str, Any]
    ai_reasoning: str | None = None
    ai_model: str | None = None


class RuleTranslationOut(BaseModel):
    id: int
    rule_id: int
    target_vendor: str
    translation: dict[str, Any]
    status: str
    ai_reasoning: str | None
    ai_model: str | None
    approved_by: str | None
    created_at: datetime
    updated_at: datetime | None


class ProposalOut(BaseModel):
    id: int
    proposal_type: str
    object_type: str | None
    object_name: str | None
    rule_id: int | None
    target_vendor: str
    proposed_translation: dict[str, Any]
    ai_reasoning: str | None
    ai_model: str | None
    triggered_by: str
    status: str
    reviewed_by: str | None
    reviewed_at: datetime | None
    created_at: datetime


class ProposalReview(BaseModel):
    action: str  # "approve" | "reject" | "modify"
    reviewed_by: str | None = None
    # For "modify": provide the corrected translation
    modified_translation: dict[str, Any] | None = None


class GapDetectionResult(BaseModel):
    target_vendor: str
    device_group_id: int
    missing_object_translations: list[dict[str, str]]
    missing_rule_translations: list[dict[str, Any]]
    proposals_created: int


class ReadinessItem(BaseModel):
    item_type: str           # "object" | "rule"
    object_type: str | None = None
    object_name: str | None = None
    rule_id: int | None = None
    rule_name: str | None = None
    rule_type: str | None = None
    # auto | approved | pending | review | rejected | not_required | none
    status: str
    proposal_id: int | None = None
    ai_model: str | None = None


class ReadinessResult(BaseModel):
    target_vendor: str
    device_group_id: int
    objects: list[ReadinessItem]
    rules: list[ReadinessItem]
    summary: dict[str, int]


# ── Helpers ───────────────────────────────────────────────────────────────────


def _obj_trans_out(t: ObjectTranslation) -> ObjectTranslationOut:
    return ObjectTranslationOut(
        id=t.id, object_type=t.object_type, object_name=t.object_name,
        target_vendor=t.target_vendor, translation=t.translation,
        status=t.status, ai_reasoning=t.ai_reasoning, ai_model=t.ai_model,
        approved_by=t.approved_by, created_at=t.created_at, updated_at=t.updated_at,
    )


def _rule_trans_out(t: RuleTranslation) -> RuleTranslationOut:
    return RuleTranslationOut(
        id=t.id, rule_id=t.rule_id, target_vendor=t.target_vendor,
        translation=t.translation, status=t.status,
        ai_reasoning=t.ai_reasoning, ai_model=t.ai_model,
        approved_by=t.approved_by, created_at=t.created_at, updated_at=t.updated_at,
    )


def _proposal_out(p: TranslationProposal) -> ProposalOut:
    return ProposalOut(
        id=p.id, proposal_type=p.proposal_type,
        object_type=p.object_type, object_name=p.object_name,
        rule_id=p.rule_id, target_vendor=p.target_vendor,
        proposed_translation=p.proposed_translation,
        ai_reasoning=p.ai_reasoning, ai_model=p.ai_model,
        triggered_by=p.triggered_by, status=p.status,
        reviewed_by=p.reviewed_by, reviewed_at=p.reviewed_at,
        created_at=p.created_at,
    )


# ── Object translations ───────────────────────────────────────────────────────


@router.get("/translations/objects", response_model=list[ObjectTranslationOut])
async def list_object_translations(
    target_vendor: str | None = None,
    object_type: str | None = None,
    status: str | None = None,
) -> list[ObjectTranslationOut]:
    async with AsyncSessionLocal() as session:
        q = select(ObjectTranslation).order_by(
            ObjectTranslation.object_type, ObjectTranslation.object_name
        )
        if target_vendor:
            q = q.where(ObjectTranslation.target_vendor == target_vendor)
        if object_type:
            q = q.where(ObjectTranslation.object_type == object_type)
        if status:
            q = q.where(ObjectTranslation.status == status)
        rows = (await session.execute(q)).scalars().all()
    return [_obj_trans_out(t) for t in rows]


@router.put("/translations/objects", response_model=ObjectTranslationOut)
async def upsert_object_translation(body: ObjectTranslationIn) -> ObjectTranslationOut:
    """Create or replace an object translation. Always sets status=approved."""
    async with AsyncSessionLocal() as session:
        existing = (await session.execute(
            select(ObjectTranslation).where(
                ObjectTranslation.object_type == body.object_type,
                ObjectTranslation.object_name == body.object_name,
                ObjectTranslation.target_vendor == body.target_vendor,
            )
        )).scalar_one_or_none()

        if existing:
            existing.translation = body.translation
            existing.status = "approved"
            existing.ai_reasoning = body.ai_reasoning
            existing.ai_model = body.ai_model
            existing.updated_at = datetime.now(timezone.utc)
            t = existing
        else:
            t = ObjectTranslation(
                object_type=body.object_type,
                object_name=body.object_name,
                target_vendor=body.target_vendor,
                translation=body.translation,
                status="approved",
                ai_reasoning=body.ai_reasoning,
                ai_model=body.ai_model,
            )
            session.add(t)

        await session.commit()
        await session.refresh(t)
    return _obj_trans_out(t)


@router.delete("/translations/objects/{translation_id}", status_code=204)
async def delete_object_translation(translation_id: int) -> None:
    async with AsyncSessionLocal() as session:
        t = await session.get(ObjectTranslation, translation_id)
        if not t:
            raise HTTPException(404, "Translation not found")
        await session.delete(t)
        await session.commit()


# ── Rule translations ─────────────────────────────────────────────────────────


@router.get("/translations/rules", response_model=list[RuleTranslationOut])
async def list_rule_translations(
    target_vendor: str | None = None,
    status: str | None = None,
    rule_id: int | None = None,
) -> list[RuleTranslationOut]:
    async with AsyncSessionLocal() as session:
        q = select(RuleTranslation)
        if target_vendor:
            q = q.where(RuleTranslation.target_vendor == target_vendor)
        if status:
            q = q.where(RuleTranslation.status == status)
        if rule_id:
            q = q.where(RuleTranslation.rule_id == rule_id)
        rows = (await session.execute(q)).scalars().all()
    return [_rule_trans_out(t) for t in rows]


@router.put("/translations/rules", response_model=RuleTranslationOut)
async def upsert_rule_translation(body: RuleTranslationIn) -> RuleTranslationOut:
    """Create or replace a rule translation. Always sets status=approved."""
    async with AsyncSessionLocal() as session:
        rule = await session.get(GroupPolicyRule, body.rule_id)
        if not rule:
            raise HTTPException(404, f"Rule {body.rule_id} not found")

        existing = (await session.execute(
            select(RuleTranslation).where(
                RuleTranslation.rule_id == body.rule_id,
                RuleTranslation.target_vendor == body.target_vendor,
            )
        )).scalar_one_or_none()

        if existing:
            existing.translation = body.translation
            existing.status = "approved"
            existing.ai_reasoning = body.ai_reasoning
            existing.ai_model = body.ai_model
            existing.updated_at = datetime.now(timezone.utc)
            t = existing
        else:
            t = RuleTranslation(
                rule_id=body.rule_id,
                target_vendor=body.target_vendor,
                translation=body.translation,
                status="approved",
                ai_reasoning=body.ai_reasoning,
                ai_model=body.ai_model,
            )
            session.add(t)

        await session.commit()
        await session.refresh(t)
    return _rule_trans_out(t)


# ── Translation proposals ─────────────────────────────────────────────────────


@router.get("/proposals", response_model=list[ProposalOut])
async def list_proposals(
    status: str = Query("pending"),
    target_vendor: str | None = None,
    proposal_type: str | None = None,
) -> list[ProposalOut]:
    async with AsyncSessionLocal() as session:
        q = (
            select(TranslationProposal)
            .where(TranslationProposal.status == status)
            .order_by(TranslationProposal.created_at)
        )
        if target_vendor:
            q = q.where(TranslationProposal.target_vendor == target_vendor)
        if proposal_type:
            q = q.where(TranslationProposal.proposal_type == proposal_type)
        rows = (await session.execute(q)).scalars().all()
    return [_proposal_out(p) for p in rows]


@router.post("/proposals/{proposal_id}/review", response_model=ProposalOut)
async def review_proposal(proposal_id: int, body: ProposalReview) -> ProposalOut:
    """Approve, reject, or modify a translation proposal.

    On approve/modify: creates the corresponding ObjectTranslation or
    RuleTranslation with status=approved.
    """
    if body.action not in ("approve", "reject", "modify"):
        raise HTTPException(400, "action must be 'approve', 'reject', or 'modify'")
    if body.action == "modify" and not body.modified_translation:
        raise HTTPException(400, "modified_translation required when action=modify")

    async with AsyncSessionLocal() as session:
        proposal = await session.get(TranslationProposal, proposal_id)
        if not proposal:
            raise HTTPException(404, "Proposal not found")
        if proposal.status != "pending":
            raise HTTPException(409, f"Proposal is already {proposal.status!r}")

        final_translation = (
            body.modified_translation
            if body.action == "modify"
            else proposal.proposed_translation
        )
        new_status = "modified" if body.action == "modify" else body.action

        proposal.status = new_status
        proposal.reviewed_by = body.reviewed_by
        proposal.reviewed_at = datetime.now(timezone.utc)
        if body.action == "modify" and body.modified_translation:
            proposal.proposed_translation = body.modified_translation

        if body.action in ("approve", "modify"):
            if proposal.proposal_type == "object":
                existing = (await session.execute(
                    select(ObjectTranslation).where(
                        ObjectTranslation.object_type == proposal.object_type,
                        ObjectTranslation.object_name == proposal.object_name,
                        ObjectTranslation.target_vendor == proposal.target_vendor,
                    )
                )).scalar_one_or_none()
                if existing:
                    existing.translation = final_translation
                    existing.status = "approved"
                    existing.ai_reasoning = proposal.ai_reasoning
                    existing.ai_model = proposal.ai_model
                    existing.approved_by = body.reviewed_by
                    existing.updated_at = datetime.now(timezone.utc)
                else:
                    session.add(ObjectTranslation(
                        object_type=proposal.object_type,
                        object_name=proposal.object_name,
                        target_vendor=proposal.target_vendor,
                        translation=final_translation,
                        status="approved",
                        ai_reasoning=proposal.ai_reasoning,
                        ai_model=proposal.ai_model,
                        approved_by=body.reviewed_by,
                    ))

            elif proposal.proposal_type == "rule" and proposal.rule_id:
                existing = (await session.execute(
                    select(RuleTranslation).where(
                        RuleTranslation.rule_id == proposal.rule_id,
                        RuleTranslation.target_vendor == proposal.target_vendor,
                    )
                )).scalar_one_or_none()
                if existing:
                    existing.translation = final_translation
                    existing.status = "approved"
                    existing.ai_reasoning = proposal.ai_reasoning
                    existing.ai_model = proposal.ai_model
                    existing.approved_by = body.reviewed_by
                    existing.updated_at = datetime.now(timezone.utc)
                else:
                    session.add(RuleTranslation(
                        rule_id=proposal.rule_id,
                        target_vendor=proposal.target_vendor,
                        translation=final_translation,
                        status="approved",
                        ai_reasoning=proposal.ai_reasoning,
                        ai_model=proposal.ai_model,
                        approved_by=body.reviewed_by,
                    ))

        await session.commit()
        await session.refresh(proposal)
    return _proposal_out(proposal)


# ── AI proposal generation ────────────────────────────────────────────────────


class GenerateResult(BaseModel):
    proposal_id: int
    status: str          # "fast_approved" | "generated" | "error"
    ai_model: str | None = None
    error: str | None = None


class BatchGenerateResult(BaseModel):
    processed: int
    fast_approved: int   # deterministic — no LLM, auto-approved
    ai_generated: int    # sent to LLM, awaiting human review
    failed: int
    results: list[GenerateResult]


@router.post("/proposals/{proposal_id}/generate", response_model=GenerateResult)
async def generate_proposal(proposal_id: int) -> GenerateResult:
    """Generate a translation for a pending proposal.

    Fast-path: deterministic object types (address, service, group, url_category,
    edl) are translated instantly without the LLM and auto-approved — status
    becomes "approved" immediately and an ObjectTranslation record is written.

    LLM-path: rules and complex objects go to the LLM; proposed_translation is
    filled in but status stays "pending" until a human approves.
    """
    async with AsyncSessionLocal() as session:
        proposal = await session.get(TranslationProposal, proposal_id)
        if not proposal:
            raise HTTPException(404, "Proposal not found")
        if proposal.status != "pending":
            raise HTTPException(409, f"Proposal is already {proposal.status!r}")

        model_name = settings.llm_model

        # ── Fetch base_data for object proposals (used by both paths) ───────────
        base_data: dict[str, Any] = {}
        if proposal.proposal_type == "object" and proposal.object_type and proposal.object_name:
            obj_row_pre = (await session.execute(
                select(GroupPolicyObject).where(
                    GroupPolicyObject.object_type == proposal.object_type,
                    GroupPolicyObject.object_name == proposal.object_name,
                )
            )).scalar_one_or_none()
            if obj_row_pre:
                base_data = obj_row_pre.base_data

        # ── Fast path for deterministic object types ──────────────────────────
        if proposal.proposal_type == "object" and proposal.object_type:
            fast = fast_translate_object(
                object_type=proposal.object_type,
                object_name=proposal.object_name or "",
                base_data=base_data,
                target_vendor=proposal.target_vendor,
            )
            if fast is not None:
                translation, reasoning = fast
                # Auto-approve: write proposal + ObjectTranslation in one shot
                proposal.proposed_translation = translation
                proposal.ai_reasoning = reasoning
                proposal.ai_model = "fast-path"
                proposal.status = "approved"
                proposal.reviewed_by = "system:fast-path"
                proposal.reviewed_at = datetime.now(timezone.utc)

                existing = (await session.execute(
                    select(ObjectTranslation).where(
                        ObjectTranslation.object_type == proposal.object_type,
                        ObjectTranslation.object_name == proposal.object_name,
                        ObjectTranslation.target_vendor == proposal.target_vendor,
                    )
                )).scalar_one_or_none()
                if existing:
                    existing.translation = translation
                    existing.status = "approved"
                    existing.ai_reasoning = reasoning
                    existing.ai_model = "fast-path"
                    existing.approved_by = "system:fast-path"
                    existing.updated_at = datetime.now(timezone.utc)
                else:
                    session.add(ObjectTranslation(
                        object_type=proposal.object_type,
                        object_name=proposal.object_name,
                        target_vendor=proposal.target_vendor,
                        translation=translation,
                        status="approved",
                        ai_reasoning=reasoning,
                        ai_model="fast-path",
                        approved_by="system:fast-path",
                    ))

                await session.commit()
                log.info(
                    "Fast-path approved: %s/%s → %s",
                    proposal.object_type, proposal.object_name, proposal.target_vendor,
                )
                return GenerateResult(
                    proposal_id=proposal_id,
                    status="fast_approved",
                    ai_model="fast-path",
                )

        # ── LLM path for rules and complex objects ────────────────────────────
        try:
            if proposal.proposal_type == "object":
                translation, reasoning = await generate_object_translation(
                    object_type=proposal.object_type or "",
                    object_name=proposal.object_name or "",
                    base_data=base_data,
                    target_vendor=proposal.target_vendor,
                    model_name=model_name,
                )

            elif proposal.proposal_type == "rule" and proposal.rule_id:
                rule = await session.get(GroupPolicyRule, proposal.rule_id)
                if not rule:
                    raise HTTPException(404, f"Rule {proposal.rule_id} not found")
                translation, reasoning = await generate_rule_translation(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    rule_type=rule.rule_type,
                    base_rule=rule.base_rule,
                    target_vendor=proposal.target_vendor,
                    model_name=model_name,
                )
            else:
                raise HTTPException(400, f"Unsupported proposal_type: {proposal.proposal_type!r}")

        except Exception as exc:
            log.warning("AI generation failed for proposal %d: %s", proposal_id, exc)
            return GenerateResult(
                proposal_id=proposal_id,
                status="error",
                ai_model=model_name,
                error=str(exc),
            )

        proposal.proposed_translation = translation
        proposal.ai_reasoning = reasoning
        proposal.ai_model = model_name
        await session.commit()

    return GenerateResult(
        proposal_id=proposal_id,
        status="generated",
        ai_model=model_name,
    )


@router.post("/proposals/generate-batch", response_model=BatchGenerateResult)
async def generate_proposals_batch(
    target_vendor: str | None = None,
    group_id: int | None = None,
    proposal_type: str | None = None,
) -> BatchGenerateResult:
    """Generate translations for all pending proposals matching the filters.

    Fast-path types (address_object, service_object, etc.) are translated
    deterministically and auto-approved in a single pass — no LLM call.
    Rule proposals go to the LLM sequentially.

    Returns a summary split by fast_approved vs ai_generated vs failed.
    """
    async with AsyncSessionLocal() as session:
        q = select(TranslationProposal).where(TranslationProposal.status == "pending")
        if target_vendor:
            q = q.where(TranslationProposal.target_vendor == target_vendor)
        if proposal_type:
            q = q.where(TranslationProposal.proposal_type == proposal_type)
        proposals = [
            p for p in (await session.execute(q)).scalars().all()
            if not p.proposed_translation
        ]

    results: list[GenerateResult] = []
    for p in proposals:
        result = await generate_proposal(p.id)
        results.append(result)

    fast_approved = sum(1 for r in results if r.status == "fast_approved")
    ai_generated  = sum(1 for r in results if r.status == "generated")
    failed        = sum(1 for r in results if r.status == "error")

    log.info(
        "Batch generate: %d proposals — %d fast-approved, %d AI-generated, %d failed",
        len(results), fast_approved, ai_generated, failed,
    )

    return BatchGenerateResult(
        processed=len(results),
        fast_approved=fast_approved,
        ai_generated=ai_generated,
        failed=failed,
        results=results,
    )


# ── Gap detection ─────────────────────────────────────────────────────────────


@router.post("/groups/{group_id}/gaps/{target_vendor}", response_model=GapDetectionResult)
async def detect_gaps(
    group_id: int,
    target_vendor: str,
    triggered_by: str = Query("manual"),
) -> GapDetectionResult:
    """Detect missing translations for target_vendor across this group's effective policy.

    Walks the full ancestor chain. For each group rule and referenced object,
    checks whether an approved translation exists. Creates TranslationProposal
    records for any gaps found. AI generation of proposed translations is
    triggered asynchronously (placeholder — proposals are created with
    proposed_translation={} until the AI fills them in).
    """
    async with AsyncSessionLocal() as session:
        from sqlalchemy import select as sel
        from src.db.models import DeviceGroup

        group = await session.get(DeviceGroup, group_id)
        if not group:
            raise HTTPException(404, f"Group {group_id} not found")

        # Collect full ancestor chain + this group
        chain: list[DeviceGroup] = []
        current = group
        while current is not None:
            chain.append(current)
            current = await session.get(DeviceGroup, current.parent_id) if current.parent_id else None
        chain.reverse()

        all_group_ids = [g.id for g in chain]

        # Collect all group-level rules across the chain
        rules = (await session.execute(
            sel(GroupPolicyRule).where(
                GroupPolicyRule.device_group_id.in_(all_group_ids)
            )
        )).scalars().all()

        # Collect all group-level objects across the chain (including shared root)
        objects = (await session.execute(
            sel(GroupPolicyObject).where(
                GroupPolicyObject.device_group_id.in_(all_group_ids + [None])  # type: ignore[list-item]
            )
        )).scalars().all()

        # Existing approved translations for this vendor
        approved_obj = {
            (t.object_type, t.object_name)
            for t in (await session.execute(
                sel(ObjectTranslation).where(
                    ObjectTranslation.target_vendor == target_vendor,
                    ObjectTranslation.status == "approved",
                )
            )).scalars().all()
        }
        approved_rule = {
            t.rule_id
            for t in (await session.execute(
                sel(RuleTranslation).where(
                    RuleTranslation.target_vendor == target_vendor,
                    RuleTranslation.status == "approved",
                )
            )).scalars().all()
        }
        # Existing pending proposals (don't create duplicates)
        pending_obj = {
            (p.object_type, p.object_name)
            for p in (await session.execute(
                sel(TranslationProposal).where(
                    TranslationProposal.target_vendor == target_vendor,
                    TranslationProposal.proposal_type == "object",
                    TranslationProposal.status == "pending",
                )
            )).scalars().all()
        }
        pending_rule = {
            p.rule_id
            for p in (await session.execute(
                sel(TranslationProposal).where(
                    TranslationProposal.target_vendor == target_vendor,
                    TranslationProposal.proposal_type == "rule",
                    TranslationProposal.status == "pending",
                )
            )).scalars().all()
        }

        missing_obj: list[dict[str, str]] = []
        missing_rule: list[dict] = []
        proposals_created = 0

        # Check object gaps
        for obj in objects:
            key = (obj.object_type, obj.object_name)
            if key not in approved_obj and key not in pending_obj:
                missing_obj.append({"object_type": obj.object_type, "object_name": obj.object_name})
                session.add(TranslationProposal(
                    proposal_type="object",
                    object_type=obj.object_type,
                    object_name=obj.object_name,
                    target_vendor=target_vendor,
                    proposed_translation={},  # AI fills this in
                    triggered_by=triggered_by,
                    status="pending",
                ))
                proposals_created += 1

        # Check rule gaps — only flag if the rule has vendor-specific fields that need translation
        for rule in rules:
            if rule.id not in approved_rule and rule.id not in pending_rule:
                base = rule.base_rule
                needs_translation = bool(
                    base.get("applications") or
                    base.get("url_categories") or
                    base.get("profiles") or
                    base.get("src_users")
                )
                if needs_translation:
                    missing_rule.append({"rule_id": rule.id, "rule_name": rule.name})
                    session.add(TranslationProposal(
                        proposal_type="rule",
                        rule_id=rule.id,
                        target_vendor=target_vendor,
                        proposed_translation={},  # AI fills this in
                        triggered_by=triggered_by,
                        status="pending",
                    ))
                    proposals_created += 1

        await session.commit()

    return GapDetectionResult(
        target_vendor=target_vendor,
        device_group_id=group_id,
        missing_object_translations=missing_obj,
        missing_rule_translations=missing_rule,
        proposals_created=proposals_created,
    )


@router.get("/groups/{group_id}/readiness/{target_vendor}", response_model=ReadinessResult)
async def get_readiness(group_id: int, target_vendor: str) -> ReadinessResult:
    """Return translation readiness for every policy item in this group's effective policy.

    Combines object/rule lists with approved translations and open proposals so
    the UI can render a single per-item status without multiple round-trips.
    """
    async with AsyncSessionLocal() as session:
        from sqlalchemy import select as sel
        from src.db.models import DeviceGroup

        group = await session.get(DeviceGroup, group_id)
        if not group:
            raise HTTPException(404, f"Group {group_id} not found")

        # Full ancestor chain (root → … → this group)
        chain: list[DeviceGroup] = []
        current = group
        while current is not None:
            chain.append(current)
            current = await session.get(DeviceGroup, current.parent_id) if current.parent_id else None
        chain.reverse()
        all_group_ids = [g.id for g in chain]

        # Collect objects and rules across the chain
        objects = (await session.execute(
            sel(GroupPolicyObject).where(
                GroupPolicyObject.device_group_id.in_(all_group_ids + [None])  # type: ignore[list-item]
            )
        )).scalars().all()

        rules = (await session.execute(
            sel(GroupPolicyRule).where(
                GroupPolicyRule.device_group_id.in_(all_group_ids)
            ).order_by(GroupPolicyRule.rulebase, GroupPolicyRule.position)
        )).scalars().all()

        # Approved object translations for this vendor
        approved_obj_trans = {
            (t.object_type, t.object_name): t
            for t in (await session.execute(
                sel(ObjectTranslation).where(
                    ObjectTranslation.target_vendor == target_vendor,
                    ObjectTranslation.status == "approved",
                )
            )).scalars().all()
        }

        # Approved rule translations for this vendor
        approved_rule_trans = {
            t.rule_id: t
            for t in (await session.execute(
                sel(RuleTranslation).where(
                    RuleTranslation.target_vendor == target_vendor,
                    RuleTranslation.status == "approved",
                )
            )).scalars().all()
        }

        # All proposals for this vendor (any status)
        obj_proposals: dict[tuple[str, str], TranslationProposal] = {}
        rule_proposals: dict[int, TranslationProposal] = {}
        for p in (await session.execute(
            sel(TranslationProposal).where(
                TranslationProposal.target_vendor == target_vendor,
            )
        )).scalars().all():
            if p.proposal_type == "object" and p.object_type and p.object_name:
                key = (p.object_type, p.object_name)
                # Prefer non-rejected over rejected
                existing = obj_proposals.get(key)
                if existing is None or existing.status == "rejected":
                    obj_proposals[key] = p
            elif p.proposal_type == "rule" and p.rule_id:
                existing_r = rule_proposals.get(p.rule_id)
                if existing_r is None or existing_r.status == "rejected":
                    rule_proposals[p.rule_id] = p

        def _obj_status(obj: GroupPolicyObject) -> ReadinessItem:
            key = (obj.object_type, obj.object_name)
            if key in approved_obj_trans:
                trans = approved_obj_trans[key]
                return ReadinessItem(
                    item_type="object",
                    object_type=obj.object_type,
                    object_name=obj.object_name,
                    status="auto" if trans.ai_model == "fast-path" else "approved",
                    ai_model=trans.ai_model,
                )
            if key in obj_proposals:
                p = obj_proposals[key]
                if p.status == "rejected":
                    return ReadinessItem(item_type="object", object_type=obj.object_type,
                                         object_name=obj.object_name, status="rejected", proposal_id=p.id)
                has_content = bool(p.proposed_translation)
                return ReadinessItem(
                    item_type="object",
                    object_type=obj.object_type,
                    object_name=obj.object_name,
                    status="review" if has_content else "pending",
                    proposal_id=p.id,
                    ai_model=p.ai_model,
                )
            return ReadinessItem(item_type="object", object_type=obj.object_type,
                                  object_name=obj.object_name, status="none")

        def _rule_status(rule: GroupPolicyRule) -> ReadinessItem:
            base = rule.base_rule
            needs = bool(
                base.get("applications") or base.get("url_categories") or
                base.get("profiles") or base.get("src_users")
            )
            if not needs:
                return ReadinessItem(item_type="rule", rule_id=rule.id,
                                      rule_name=rule.name, rule_type=rule.rule_type,
                                      status="not_required")
            if rule.id in approved_rule_trans:
                trans = approved_rule_trans[rule.id]
                return ReadinessItem(item_type="rule", rule_id=rule.id,
                                      rule_name=rule.name, rule_type=rule.rule_type,
                                      status="approved", ai_model=trans.ai_model)
            if rule.id in rule_proposals:
                p = rule_proposals[rule.id]
                if p.status == "rejected":
                    return ReadinessItem(item_type="rule", rule_id=rule.id,
                                          rule_name=rule.name, rule_type=rule.rule_type,
                                          status="rejected", proposal_id=p.id)
                has_content = bool(p.proposed_translation)
                return ReadinessItem(item_type="rule", rule_id=rule.id,
                                      rule_name=rule.name, rule_type=rule.rule_type,
                                      status="review" if has_content else "pending",
                                      proposal_id=p.id, ai_model=p.ai_model)
            return ReadinessItem(item_type="rule", rule_id=rule.id,
                                  rule_name=rule.name, rule_type=rule.rule_type, status="none")

        obj_items = [_obj_status(o) for o in objects]
        rule_items = [_rule_status(r) for r in rules]
        all_items = obj_items + rule_items

        summary: dict[str, int] = {}
        for item in all_items:
            summary[item.status] = summary.get(item.status, 0) + 1

    return ReadinessResult(
        target_vendor=target_vendor,
        device_group_id=group_id,
        objects=obj_items,
        rules=rule_items,
        summary=summary,
    )
