"""Pluggable LLM and embedding provider factory.

Chat and embedding providers are configured independently because not every
LLM provider offers embedding models (e.g. Anthropic has none). A common
production setup is Claude or GPT-4o for chat + OpenAI/Ollama for embeddings.

Configuration (via .env):
    LLM_PROVIDER     = ollama | openai | anthropic   (default: ollama)
    LLM_MODEL        = model name for the chat provider
    EMBED_PROVIDER   = ollama | openai               (default: ollama)
    EMBED_MODEL      = model name for the embedding provider

    OLLAMA_BASE_URL  = http://host.docker.internal:11434
    OPENAI_API_KEY   = sk-...
    ANTHROPIC_API_KEY= sk-ant-...
"""
from __future__ import annotations

from functools import lru_cache

from langchain_core.embeddings import Embeddings
from langchain_core.language_models import BaseChatModel

from src.config import settings


@lru_cache(maxsize=1)
def get_chat_llm() -> BaseChatModel:
    """Return a cached chat LLM instance for the configured provider."""
    provider = settings.llm_provider

    if provider == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(
            base_url=settings.ollama_base_url,
            model=settings.llm_model,
            temperature=0.1,
        )

    if provider == "openai":
        try:
            from langchain_openai import ChatOpenAI
        except ImportError:
            raise ImportError(
                "langchain-openai is required for OpenAI support. "
                "Install it with: pip install langchain-openai"
            )
        if not settings.openai_api_key:
            raise ValueError("OPENAI_API_KEY must be set when LLM_PROVIDER=openai")
        return ChatOpenAI(
            api_key=settings.openai_api_key,
            model=settings.llm_model,
            temperature=0.1,
        )

    if provider == "anthropic":
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError:
            raise ImportError(
                "langchain-anthropic is required for Anthropic support. "
                "Install it with: pip install langchain-anthropic"
            )
        if not settings.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY must be set when LLM_PROVIDER=anthropic")
        return ChatAnthropic(
            api_key=settings.anthropic_api_key,
            model=settings.llm_model,
            temperature=0.1,
        )

    raise ValueError(
        f"Unknown LLM_PROVIDER '{provider}'. Choose: ollama | openai | anthropic"
    )


@lru_cache(maxsize=1)
def get_embeddings() -> Embeddings:
    """Return a cached embedding model instance for the configured provider.

    Note: Anthropic does not offer embedding models. Use ollama or openai
    for EMBED_PROVIDER even when LLM_PROVIDER=anthropic.
    """
    provider = settings.embed_provider

    if provider == "ollama":
        from langchain_ollama import OllamaEmbeddings
        return OllamaEmbeddings(
            base_url=settings.ollama_base_url,
            model=settings.embed_model,
        )

    if provider == "openai":
        try:
            from langchain_openai import OpenAIEmbeddings
        except ImportError:
            raise ImportError(
                "langchain-openai is required for OpenAI embeddings. "
                "Install it with: pip install langchain-openai"
            )
        if not settings.openai_api_key:
            raise ValueError("OPENAI_API_KEY must be set when EMBED_PROVIDER=openai")
        return OpenAIEmbeddings(
            api_key=settings.openai_api_key,
            model=settings.embed_model or "text-embedding-3-small",
        )

    raise ValueError(
        f"Unknown EMBED_PROVIDER '{provider}'. Choose: ollama | openai"
    )


def invalidate_cache() -> None:
    """Clear the LRU caches — used when config changes at runtime."""
    get_chat_llm.cache_clear()
    get_embeddings.cache_clear()
