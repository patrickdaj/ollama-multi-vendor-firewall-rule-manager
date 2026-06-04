"""FastAPI application entry point."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import uvicorn
from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from src.api.routes import chat, firewall, rag
from src.api.routes import devices as devices_router
from src.api.routes import groups as groups_router
from src.api.routes import push as push_router
from src.api.routes import settings as settings_router
from src.api.routes import snapshots as snapshots_router
from src.api.routes import tasks as tasks_router
from src.api.routes import translations as translations_router
from src.api.ws.agent_manager import agent_manager
from src.api.ws.manager import manager
from src.config import settings

STATIC_DIR = Path(__file__).parent / "static"
ALEMBIC_INI = Path(__file__).resolve().parent.parent.parent / "alembic.ini"

logging.basicConfig(level=settings.app_log_level)
log = logging.getLogger(__name__)

app = FastAPI(
    title="Firewall RAG Manager",
    description="Multi-vendor firewall rule management with RAG + chat",
    version="0.1.0",
)


@app.on_event("startup")
async def startup() -> None:
    def _run_migrations() -> None:
        cfg = AlembicConfig(str(ALEMBIC_INI))
        alembic_command.upgrade(cfg, "head")

    log.info("Running database migrations…")
    await asyncio.get_running_loop().run_in_executor(None, _run_migrations)
    log.info("Migrations complete.")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# REST routers
app.include_router(chat.router, prefix="/api/v1")
app.include_router(firewall.router, prefix="/api/v1")
app.include_router(rag.router, prefix="/api/v1")
app.include_router(devices_router.router, prefix="/api/v1")
app.include_router(snapshots_router.router, prefix="/api/v1")
app.include_router(groups_router.router, prefix="/api/v1")
app.include_router(translations_router.router, prefix="/api/v1")
app.include_router(push_router.router, prefix="/api/v1")
app.include_router(settings_router.router, prefix="/api/v1")
app.include_router(tasks_router.router, prefix="/api/v1")


@app.get("/health", tags=["meta"])
@app.get("/api/v1/health", tags=["meta"], include_in_schema=False)
async def health() -> dict:
    from importlib.metadata import version as pkg_version, PackageNotFoundError
    try:
        v = pkg_version("ollama-multi-vendor-firewall-rule-manager")
    except PackageNotFoundError:
        v = "0.1.0"
    return {"status": "ok", "env": settings.app_env, "version": v}


@app.websocket("/ws/agent/{session_id}")
async def websocket_agent(websocket: WebSocket, session_id: str) -> None:
    """
    Ignis AI agent WebSocket — streaming chat with tool calling.

    Extended protocol over the basic chat endpoint:
      Client sends: {"action": "chat",    "message": "..."}
                    {"action": "clear"}
                    {"action": "restore"}  ← request history on reconnect
      Server sends:
        {"type": "start"}
        {"type": "token",      "content": "..."}
        {"type": "task_start", "task_id": "...", "tool": "...", "description": "..."}
        {"type": "task_done",  "task_id": "...", "result": "...", "invalidate": [...]}
        {"type": "task_error", "task_id": "...", "error": "..."}
        {"type": "end",        "history": [...]}
        {"type": "history",    "history": [...]}   ← response to "restore"
        {"type": "cleared"}
    """
    await agent_manager.handle(session_id, websocket)


@app.websocket("/ws/chat/{session_id}")
async def websocket_chat(websocket: WebSocket, session_id: str) -> None:
    """
    Streaming WebSocket chat endpoint.

    Client sends: {"action": "chat", "message": "..."}
    Server sends:
      {"type": "start"}
      {"type": "token", "content": "..."}   (repeated)
      {"type": "end", "history": [...]}
    """
    await manager.handle(session_id, websocket)


if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str) -> FileResponse:
        candidate = STATIC_DIR / full_path
        if candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(STATIC_DIR / "index.html")


def run() -> None:
    uvicorn.run(
        "src.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.app_env == "development",
        log_level=settings.app_log_level.lower(),
    )


if __name__ == "__main__":
    run()
