"""WebSocket handler for the Ignis AI agent endpoint.

Extends the basic chat protocol with task_start / task_done / task_error
events that the AiDock frontend tracks in a persistent task queue.
"""
from __future__ import annotations

import json
import logging

from fastapi import WebSocket

from src.chat.agent import stream_agent

log = logging.getLogger(__name__)

# Per-session conversation history (in-process; Phase 3.5 will move to Redis)
_histories: dict[str, list[dict]] = {}


class AgentConnectionManager:
    def __init__(self) -> None:
        self._active: dict[str, WebSocket] = {}

    async def handle(self, session_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self._active[session_id] = ws
        log.info("Agent WS connected: %s", session_id)

        try:
            while True:
                data = await ws.receive_text()
                msg = json.loads(data)
                action = msg.get("action", "chat")

                if action == "clear":
                    _histories.pop(session_id, None)
                    await ws.send_json({"type": "cleared"})
                    continue

                if action == "restore":
                    # Client asks for history on reconnect
                    history = _histories.get(session_id, [])
                    await ws.send_json({"type": "history", "history": history})
                    continue

                user_message: str = msg.get("message", "").strip()
                if not user_message:
                    continue

                history = _histories.get(session_id, [])
                await ws.send_json({"type": "start"})

                async for event in stream_agent(user_message, history):
                    await ws.send_json(event)
                    if event.get("type") == "end":
                        _histories[session_id] = event.get("history", history)

        except Exception as exc:
            log.warning("Agent WS %s ended: %s", session_id, exc)
        finally:
            self._active.pop(session_id, None)
            log.info("Agent WS disconnected: %s", session_id)


agent_manager = AgentConnectionManager()
