"""ChromaDB vector store setup and singleton access."""
from __future__ import annotations

import chromadb
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

from src.config import settings

_store: Chroma | None = None


def _embeddings() -> OllamaEmbeddings:
    return OllamaEmbeddings(
        base_url=settings.ollama_base_url,
        model=settings.ollama_embed_model,
    )


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
            embedding_function=_embeddings(),
        )
    return _store


def reset_vectorstore() -> None:
    """Clear the module-level singleton (useful in tests)."""
    global _store
    _store = None
