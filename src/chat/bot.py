"""Chat bot with conversation memory backed by the firewall RAG chain."""
from __future__ import annotations

import logging
from collections import deque
from typing import AsyncIterator

from langchain_core.messages import AIMessage, HumanMessage
from langchain_ollama import ChatOllama

from src.config import settings
from src.rag.chain import build_rag_chain, get_retriever, messages_to_history

logger = logging.getLogger(__name__)

MAX_HISTORY = 20  # max turns kept in memory per session


class FirewallChatBot:
    """Stateful chatbot for a single user session."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self._history: deque[dict] = deque(maxlen=MAX_HISTORY * 2)
        self._chain = build_rag_chain()

    def _add_turn(self, role: str, content: str) -> None:
        self._history.append({"role": role, "content": content})

    @property
    def history(self) -> list[dict]:
        return list(self._history)

    async def chat(self, user_message: str) -> str:
        """Single turn — returns full answer string."""
        lc_history = messages_to_history(list(self._history))
        answer: str = await self._chain.ainvoke(
            {"input": user_message, "chat_history": lc_history}
        )
        self._add_turn("user", user_message)
        self._add_turn("assistant", answer)
        return answer

    async def stream(self, user_message: str) -> AsyncIterator[str]:
        """Streaming turn — yields answer tokens as they arrive."""
        lc_history = messages_to_history(list(self._history))
        llm = ChatOllama(
            base_url=settings.ollama_base_url,
            model=settings.ollama_chat_model,
            temperature=0.1,
        )
        # For streaming we use the LLM directly with retrieved context
        retriever = get_retriever()
        vs_results = await retriever.ainvoke(user_message)
        context = "\n\n".join(d.page_content for d in vs_results)

        messages = [
            *lc_history,
            HumanMessage(
                content=(
                    f"Context from firewall knowledge base:\n{context}\n\n"
                    f"Question: {user_message}"
                )
            ),
        ]

        full_response = ""
        async for chunk in llm.astream(messages):
            token = chunk.content
            full_response += token
            yield token

        self._add_turn("user", user_message)
        self._add_turn("assistant", full_response)

    def clear_history(self) -> None:
        self._history.clear()


# ── Session registry ────────────────────────────────────────────────────────

_sessions: dict[str, FirewallChatBot] = {}


def get_session(session_id: str) -> FirewallChatBot:
    if session_id not in _sessions:
        _sessions[session_id] = FirewallChatBot(session_id)
    return _sessions[session_id]


def clear_session(session_id: str) -> None:
    _sessions.pop(session_id, None)
