"""Huey task queue — background worker for long-running LLM operations.

Uses SqliteHuey so no extra infrastructure is needed beyond the existing
Postgres + ChromaDB stack.  The SQLite file lives in /app/data/huey.db and
is shared between the API container and the worker container via a volume.

Worker startup (added to docker-compose):
    python -m huey.bin.huey_consumer src.tasks -w 1 -k thread
"""
from huey import SqliteHuey

from src.config import settings

huey = SqliteHuey(
    name="ignis",
    filename=str(settings.huey_db_path),
    results=True,
    store_none=False,
    utc=True,
)

# Import task modules so their @huey.task decorators register with this instance
from src.tasks import import_tasks, gap_tasks, push_tasks  # noqa: E402, F401
