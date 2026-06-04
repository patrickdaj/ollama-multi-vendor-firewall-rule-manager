"""CLI entry point — interactive terminal chat."""
from __future__ import annotations

import asyncio
import uuid

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.prompt import Prompt

from src.chat.bot import FirewallChatBot

cli_app = typer.Typer(help="Firewall RAG Manager CLI")
console = Console()


@cli_app.command()
def chat(
    session: str = typer.Option(None, help="Session ID (auto-generated if not provided)"),
    model: str = typer.Option(None, help="Override Ollama chat model"),
) -> None:
    """Start an interactive firewall policy chat session."""
    if model:
        from src import config
        config.settings.ollama_chat_model = model

    sid = session or str(uuid.uuid4())[:8]
    bot = FirewallChatBot(sid)
    console.print(f"[bold green]Firewall RAG Chat[/] — session [cyan]{sid}[/]")
    console.print("Type [bold]exit[/] or [bold]quit[/] to end. Type [bold]clear[/] to reset history.\n")

    async def _run() -> None:
        while True:
            try:
                user_input = Prompt.ask("[bold blue]You[/]")
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Goodbye.[/]")
                break

            if user_input.lower() in ("exit", "quit"):
                console.print("[dim]Goodbye.[/]")
                break
            if user_input.lower() == "clear":
                bot.clear_history()
                console.print("[dim]History cleared.[/]")
                continue

            console.print("[bold yellow]Assistant:[/] [dim]▌[/]", end="\r")
            full = ""
            async for token in bot.stream(user_input):
                full += token
            console.print(Markdown(full))

    asyncio.run(_run())


@cli_app.command()
def ingest(device: str = typer.Argument(help="Device name from FIREWALL_DEVICES")) -> None:
    """Fetch a device policy and ingest it into the vector store."""
    from src.config import settings
    from src.firewall.vendors import get_connector
    from src.rag.loader import ingest_policy

    dev = settings.get_device(device)
    if not dev:
        console.print(f"[red]Device '{device}' not found in FIREWALL_DEVICES[/]")
        raise typer.Exit(1)

    async def _run() -> None:
        connector = get_connector(dev)
        async with connector:
            policy = await connector.get_policy()
        count = ingest_policy(policy)
        console.print(f"[green]Ingested {count} documents from {device} ({dev.vendor})[/]")

    asyncio.run(_run())


if __name__ == "__main__":
    cli_app()
