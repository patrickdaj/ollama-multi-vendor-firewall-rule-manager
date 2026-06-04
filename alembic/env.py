"""Alembic environment — async SQLAlchemy + asyncpg."""
from __future__ import annotations

import asyncio
import logging
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import context

# Import project settings and models so autogenerate sees the full schema.
from src.config import settings
from src.db.models import Base

# Alembic Config object — gives access to values in alembic.ini.
config = context.config

# Override the sqlalchemy.url from application settings so we never
# hard-code credentials anywhere.
config.set_main_option("sqlalchemy.url", settings.database_url)

# Set up logging as configured in alembic.ini.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

logger = logging.getLogger("alembic.env")

# Point autogenerate at our model metadata.
target_metadata = Base.metadata


# ── Offline mode (generates SQL without a live DB connection) ─────────────────


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ── Online mode (connects to the real database) ───────────────────────────────


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = create_async_engine(
        settings.database_url,
        poolclass=pool.NullPool,  # fresh connection per migration run
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations() -> None:
    if context.is_offline_mode():
        run_migrations_offline()
    else:
        asyncio.run(run_migrations_online())


run_migrations()
