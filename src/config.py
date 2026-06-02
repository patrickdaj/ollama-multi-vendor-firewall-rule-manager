from __future__ import annotations

import json
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DeviceConfig(BaseSettings):
    """A single managed firewall device."""

    name: str
    vendor: Literal["paloalto", "cisco_asa", "cisco_ftd", "fortinet"]
    host: str
    username: str
    password: str
    port: int = 22
    # Vendor-specific overrides
    api_key: str | None = None       # PAN-OS API key
    verify_ssl: bool = True
    timeout: int = 30


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Ollama
    ollama_base_url: str = "http://localhost:11434"
    ollama_chat_model: str = "llama3.2"
    ollama_embed_model: str = "nomic-embed-text"

    # ChromaDB
    chroma_host: str = "localhost"
    chroma_port: int = 8000
    chroma_collection: str = "firewall_policies"

    # API
    app_env: Literal["development", "production"] = "development"
    app_log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8080

    # Device registry — stored as JSON string in env
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
        return next((d for d in self.firewall_devices if d.name == name), None)


settings = Settings()
