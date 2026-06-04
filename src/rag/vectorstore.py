"""ChromaDB vector store setup and singleton access."""
from __future__ import annotations

import chromadb
from langchain_chroma import Chroma

from src.config import settings
from src.llm.factory import get_embeddings

_store: Chroma | None = None


def build_filter(where: dict) -> dict | None:
    """Convert a flat metadata dict to a ChromaDB 1.x compatible where clause.

    ChromaDB 1.x requires $and for multiple conditions; a single condition
    can use implicit equality via {"field": {"$eq": value}}.
    """
    if not where:
        return None
    if len(where) == 1:
        k, v = next(iter(where.items()))
        return {k: {"$eq": v}}
    return {"$and": [{k: {"$eq": v}} for k, v in where.items()]}


def get_vectorstore() -> Chroma:
    global _store
    if _store is None:
        client = chromadb.HttpClient(
            host=settings.chroma_host,
            port=settings.chroma_port,
        )
        _store = Chroma(
            client=client,
            collection_name=settings.chroma_collection,
            embedding_function=get_embeddings(),
        )
    return _store


def reset_vectorstore() -> None:
    """Clear the module-level singleton (useful in tests)."""
    global _store
    _store = None
