from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DeviceConfig(BaseSettings):
    """A single managed firewall device — connection parameters + credentials."""

    name: str
    vendor: Literal["paloalto", "cisco_asa", "cisco_asa_ssh", "cisco_ftd", "fortinet"]
    host: str
    username: str = ""
    password: str = ""
    port: int = 22
    api_key: str | None = None
    verify_ssl: bool = True
    timeout: int = 30

    model_config = SettingsConfigDict(extra="ignore")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # LLM provider — ollama | openai | anthropic
    llm_provider: str = "ollama"
    llm_model: str = "llama3.2"

    # Embedding provider — ollama | openai
    embed_provider: str = "ollama"
    embed_model: str = "nomic-embed-text"

    # Ollama (used when llm_provider or embed_provider = "ollama")
    ollama_base_url: str = "http://localhost:11434"

    # API keys
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None

    # Database
    database_url: str = "postgresql+asyncpg://fwmgr:fwmgr@localhost:5432/firewall_manager"
    encryption_key: str = ""

    # ChromaDB
    chroma_host: str = "localhost"
    chroma_port: int = 8000
    chroma_collection: str = "firewall_policies"

    # Task queue
    huey_db_path: Path = Path("/app/data/huey.db")

    # API
    app_env: Literal["development", "production"] = "development"
    app_log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8080

    # Legacy device registry — FIREWALL_DEVICES env var (credentials fallback)
    # New devices should be registered via POST /api/v1/devices instead.
    firewall_devices: list[DeviceConfig] = Field(default_factory=list)

    @field_validator("firewall_devices", mode="before")
    @classmethod
    def parse_devices(cls, v: str | list) -> list:
        if isinstance(v, str):
            raw = json.loads(v)
            return [DeviceConfig(**d) for d in raw]
        return v

    @property
    def chroma_url(self) -> str:
        return f"http://{self.chroma_host}:{self.chroma_port}"

    def get_device(self, name: str) -> DeviceConfig | None:
        """Look up a device by name.

        Resolution order:
        1. Postgres devices table (authoritative — has host, port, verify_ssl)
           combined with encrypted credentials decrypted at call time.
        2. FIREWALL_DEVICES env var (legacy fallback).

        This method is intentionally synchronous for use outside async contexts.
        Use get_device_async() in async handlers for better performance.
        """
        # Try Postgres first (sync via psycopg2-compatible approach won't work
        # with asyncpg — use the env fallback synchronously, let async callers
        # use get_device_async instead)
        env_device = next((d for d in self.firewall_devices if d.name == name), None)
        return env_device

    async def get_device_async(self, name: str) -> DeviceConfig | None:
        """Async device lookup — queries Postgres first, falls back to env."""
        from sqlalchemy import select
        from src.db.models import Device as DeviceModel
        from src.db.session import AsyncSessionLocal
        from src.security.credentials import decrypt_credentials

        async with AsyncSessionLocal() as session:
            row = (await session.execute(
                select(DeviceModel).where(DeviceModel.name == name)
            )).scalar_one_or_none()

        if row:
            creds: dict = {}
            if row.credentials_enc:
                try:
                    creds = decrypt_credentials(row.credentials_enc)
                except Exception:
                    pass
            # Merge with env credentials if available (env takes precedence for secrets)
            env_dev = next((d for d in self.firewall_devices if d.name == name), None)
            if env_dev:
                creds = {
                    "username": env_dev.username or creds.get("username", ""),
                    "password": env_dev.password or creds.get("password", ""),
                    "api_key": env_dev.api_key or creds.get("api_key"),
                }
            return DeviceConfig(
                name=row.name,
                vendor=row.vendor,
                host=row.host or "",
                port=row.port or 22,
                verify_ssl=row.verify_ssl,
                username=creds.get("username", ""),
                password=creds.get("password", ""),
                api_key=creds.get("api_key"),
            )

        # Fall back to env
        return next((d for d in self.firewall_devices if d.name == name), None)


settings = Settings()
