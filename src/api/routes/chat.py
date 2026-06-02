"""Chat REST endpoints."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from src.chat.bot import clear_session, get_session

router = APIRouter(prefix="/chat", tags=["chat"])


class ChatRequest(BaseModel):
    session_id: str
    message: str


class ChatResponse(BaseModel):
    session_id: str
    answer: str
    history: list[dict]


@router.post("", response_model=ChatResponse)
async def chat(req: ChatRequest) -> ChatResponse:
    """Single-turn chat (non-streaming)."""
    bot = get_session(req.session_id)
    answer = await bot.chat(req.message)
    return ChatResponse(session_id=req.session_id, answer=answer, history=bot.history)


@router.delete("/{session_id}")
async def clear_chat(session_id: str) -> dict:
    clear_session(session_id)
    return {"cleared": session_id}
