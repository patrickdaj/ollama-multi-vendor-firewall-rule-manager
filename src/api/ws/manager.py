"""WebSocket connection manager for streaming chat."""
from __future__ import annotations

import json
import logging

from fastapi import WebSocket

from src.chat.bot import clear_session, get_session

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self._active: dict[str, WebSocket] = {}

    async def connect(self, session_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self._active[session_id] = ws
        logger.info("WS connected: %s", session_id)

    def disconnect(self, session_id: str) -> None:
        self._active.pop(session_id, None)
        logger.info("WS disconnected: %s", session_id)

    async def handle(self, session_id: str, ws: WebSocket) -> None:
        await self.connect(session_id, ws)
        try:
            while True:
                data = await ws.receive_text()
                msg = json.loads(data)
                action = msg.get("action", "chat")

                if action == "clear":
                    clear_session(session_id)
                    await ws.send_json({"type": "cleared"})
                    continue

                user_message: str = msg.get("message", "")
                if not user_message:
                    continue

                bot = get_session(session_id)
                await ws.send_json({"type": "start"})

                async for token in bot.stream(user_message):
                    await ws.send_json({"type": "token", "content": token})

                await ws.send_json({"type": "end", "history": bot.history})

        except Exception as e:
            logger.warning("WS session %s ended: %s", session_id, e)
        finally:
            self.disconnect(session_id)


manager = ConnectionManager()
