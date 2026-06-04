"""Task status endpoint — lets the frontend poll Huey task results."""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from huey.exceptions import TaskException
from pydantic import BaseModel

from src.tasks import huey

router = APIRouter(prefix="/tasks", tags=["tasks"])
log = logging.getLogger(__name__)


class TaskStatus(BaseModel):
    task_id: str
    status: str          # queued | running | complete | error
    result: dict | None = None
    error: str | None = None


@router.get("/{task_id}", response_model=TaskStatus)
async def get_task_status(task_id: str) -> TaskStatus:
    """Poll the status of a background task.

    Returns:
      - status="queued"   — task is enqueued but not yet picked up
      - status="running"  — worker has started the task (Huey doesn't distinguish
                            queued/running without a heartbeat table, so both map
                            to "pending" until the result arrives)
      - status="complete" — result is ready
      - status="error"    — task raised an exception; error field contains detail
    """
    try:
        # peek=True keeps the result in the store so subsequent polls work
        raw = huey.get(task_id, peek=True)
    except Exception as exc:
        log.warning("Unexpected error fetching task %s: %s", task_id, exc)
        raise HTTPException(500, f"Could not retrieve task status: {exc}")

    if raw is None:
        return TaskStatus(task_id=task_id, status="pending")

    # Huey wraps errors in an Error result object
    from huey.api import Error
    if isinstance(raw, Error):
        return TaskStatus(task_id=task_id, status="error", error=str(raw.metadata))

    return TaskStatus(task_id=task_id, status="complete", result=raw)
