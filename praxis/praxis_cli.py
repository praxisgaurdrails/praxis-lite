"""
Praxis CLI — the command you run to drive Praxis yourself.

    praxis doctor                      Check environment (python, ollama, deps)
    praxis daemon start [--foreground] Start the background daemon
    praxis daemon stop                 Stop it
    praxis daemon status               Show daemon + connectivity status
    praxis search <query> [--path P]   Find files by name (the local RAG)
    praxis read <path>                 Read a file (blocked on secrets)
    praxis delete <path>...            Delete (staged to trash, recoverable)
    praxis trash list|restore <id>     Manage the staged trash
    praxis ask "<text>"                Offline: local LLM plans + runs tools
    praxis guard <action> ...          Evaluate an AGENT action (the guardrail)
    praxis evidence [--limit N]        Show the hash-chained audit log

The guardrail is the core: `praxis guard` shows exactly what Praxis
decides for a browser / filesystem action from an external agent vs.
from you. Everything is recorded in a tamper-evident chain.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

from praxis.daemon import DaemonConfig, PraxisDaemon, DEFAULT_STATE_DIR


STATE_DIR = Path(os.environ.get("PRAXIS_STATE_DIR", str(DEFAULT_STATE_DIR)))
SOCKET_PATH = STATE_DIR / "socket"
PID_FILE = STATE_DIR / "daemon.pid"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_local_key() -> bytes:
    from praxis.principal import ensure_local_key

    return ensure_local_key(STATE_DIR / "local_key")


def _daemon_pid() -> int | None:
    if not PID_FILE.exists():
        return None
    try:
        pid = int(PID_FILE.read_text().strip())
    except (ValueError, OSError):
        return None
    # Is it actually alive?
    try:
        os.kill(pid, 0)
        return pid
    except OSError:
        return None


async def _socket_call(op: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    """Open the local socket, do one call, close."""
    from praxis.transports import LocalSocketClient

    key = _load_local_key()
    client = LocalSocketClient(local_key=key, socket_path=SOCKET_PATH)
    try:
        await client.connect()
    except Exception as e:
        raise click.ClickException(
            f"Cannot reach the Praxis daemon at {SOCKET_PATH}.\n"
            f"Is it running?  Start it with:  praxis daemon start\n"
            f"({e})"
        )
    try:
        return await client.call(op, args or {})
    finally:
        await client.close()


def _print_fs_result(r: dict[str, Any]) -> None:
    status = r.get("status", "?")
    if r.get("ok"):
        console.print(f"[green]✓[/] {status}")
    elif status == "blocked":
        console.print(
            f"[red]✗ BLOCKED[/] — {r.get('reason','')}  "
            f"[dim](rule: {r.get('decision_matched_rule','')})[/]"
        )
    elif status.startswith("approval"):
        console.print(f"[yellow]⏸ {status}[/] — {r.get('reason','')}")
    else:
        console.print(f"[yellow]{status}[/] — {r.get('reason','')}")


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(version=__import__("praxis").__version__, prog_name="praxis")
def main() -> None:
    """🛡️  Praxis — the guardrail for agentic AI + your offline file assistant."""
    pass


# ---------------------------------------------------------------------------
# mcp — passthrough so the frozen binary can act as the MCP server
# ---------------------------------------------------------------------------


@main.command(
    "mcp",
    context_settings=dict(ignore_unknown_options=True, allow_extra_args=True),
    add_help_option=False,
)
@click.argument("mcp_args", nargs=-1, type=click.UNPROCESSED)
def mcp(mcp_args: tuple[str, ...]) -> None:
    """Run Praxis as an MCP server (used by AI clients; args passed through)."""
    from praxis.mcp.praxis_server import main as mcp_main

    raise SystemExit(mcp_main(list(mcp_args)))


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


@main.command()
def edition() -> None:
    """Show whether this is the free (Lite) or paid (Full) edition."""
    from praxis.edition import detect_edition

    ed = detect_edition()
    color = "green" if ed.is_full else "cyan"
    lines = [
        f"[bold {color}]Praxis {ed.name} edition[/]\n",
        f"  browser guardrail:   {'[green]✓[/]' if ed.browser_guardrail else '[dim]— (Full only)[/]'}",
        f"  REST sidecar:        {'[green]✓[/]' if ed.rest_sidecar else '[dim]— (Full only)[/]'}",
        f"  web dashboard:       {'[green]✓[/]' if ed.dashboard else '[dim]— (Full only)[/]'}",
        f"  NLP semantic match:  {'[green]✓[/]' if ed.semantic_matching else '[dim]— (Full only)[/]'}",
        f"  MCP filesystem guard:[green]✓[/] (always)",
    ]
    if not ed.is_full:
        lines.append(
            "\n[dim]Upgrade to Full for the browser guardrail, OpenClaw "
            "integration,\ndashboard, and smarter intent detection: "
            "https://praxis.app/#pricing[/]"
        )
    console.print(Panel("\n".join(lines), border_style=color, title="Edition"))


@main.command()
def doctor() -> None:
    """Check that everything Praxis needs is in place."""
    table = Table(title="Praxis environment check", box=box.ROUNDED)
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("Detail", style="dim")

    # Python version
    v = sys.version_info
    ok_py = v >= (3, 11)
    table.add_row(
        "Python >= 3.11",
        "[green]ok[/]" if ok_py else "[red]too old[/]",
        f"{v.major}.{v.minor}.{v.micro}",
    )

    # Core deps
    for mod in ("pydantic", "click", "rich", "httpx", "rapidfuzz", "aiofiles"):
        try:
            __import__(mod)
            table.add_row(f"dep: {mod}", "[green]ok[/]", "")
        except ImportError:
            table.add_row(f"dep: {mod}", "[red]missing[/]", f"pip install {mod}")

    # Search backend
    try:
        from praxis.filesystem import pick_default_backend

        backend = pick_default_backend()
        table.add_row("search backend", "[green]ok[/]", backend.name)
    except Exception as e:
        table.add_row("search backend", "[red]error[/]", str(e))

    # Ollama
    async def _check_ollama():
        from praxis.llm import OllamaBackend

        b = OllamaBackend()
        if await b.is_available():
            models = await b.list_models()
            return True, ", ".join(models[:5]) or "(no models pulled)"
        return False, "not running"

    try:
        ok_ollama, detail = asyncio.run(_check_ollama())
        table.add_row(
            "Ollama (offline LLM)",
            "[green]ok[/]" if ok_ollama else "[yellow]optional[/]",
            detail if ok_ollama else "install from ollama.com for `praxis ask`",
        )
    except Exception as e:
        table.add_row("Ollama (offline LLM)", "[yellow]optional[/]", str(e))

    # Daemon
    pid = _daemon_pid()
    table.add_row(
        "daemon",
        "[green]running[/]" if pid else "[dim]stopped[/]",
        f"pid {pid}" if pid else "start with `praxis daemon start`",
    )

    console.print(table)


# ---------------------------------------------------------------------------
# daemon group
# ---------------------------------------------------------------------------


@main.group()
def daemon() -> None:
    """Start / stop / inspect the background daemon."""
    pass


@daemon.command("start")
@click.option("--foreground", is_flag=True, help="Run in this terminal (Ctrl-C to stop)")
@click.option("--auto-approve", is_flag=True, help="Auto-approve writes/deletes (TESTING ONLY)")
@click.option("--rest", is_flag=True, help="Also expose the REST sidecar on :18790")
def daemon_start(foreground: bool, auto_approve: bool, rest: bool) -> None:
    """Start the Praxis daemon."""
    existing = _daemon_pid()
    if existing:
        console.print(f"[yellow]Daemon already running (pid {existing}).[/]")
        return

    config = DaemonConfig(
        state_dir=STATE_DIR,
        enable_rest=rest,
        enable_connectivity=True,
        auto_approve=auto_approve,
        log_level="INFO" if foreground else "WARNING",
    )

    if foreground:
        console.print(
            Panel.fit(
                "[bold cyan]🛡️  Praxis daemon[/]\n\n"
                f"socket: {config.resolved_socket_path()}\n"
                f"state:  {STATE_DIR}\n"
                f"auto-approve: {auto_approve}\n"
                f"rest: {rest}\n\n"
                "[dim]Ctrl-C to stop.  Open another terminal to run "
                "`praxis search ...`[/]",
                border_style="cyan",
            )
        )
        d = PraxisDaemon(config)
        try:
            asyncio.run(d.run())
        except KeyboardInterrupt:
            pass
        return

    # Background: re-exec ourselves detached.
    import subprocess
    import os as _os

    child_env = dict(_os.environ)
    child_env["PRAXIS_STATE_DIR"] = str(STATE_DIR)

    if getattr(sys, "frozen", False):
        # Frozen bundle: sys.executable is the praxis binary itself.
        # Re-invoke our own `daemon start --foreground` in a subprocess;
        # the state dir travels via the env var (read by this module).
        args = [sys.executable, "daemon", "start", "--foreground"]
    else:
        args = [sys.executable, "-m", "praxis.daemon",
                "--state-dir", str(STATE_DIR)]
    if auto_approve:
        args.append("--auto-approve")
    if rest:
        args.append("--rest")
    log_path = STATE_DIR / "daemon.log"
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    logf = open(log_path, "a")
    proc = subprocess.Popen(
        args,
        stdout=logf,
        stderr=logf,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        env=child_env,
    )
    if _daemon_pid() or proc.poll() is None:
        console.print(
            f"[green]✓ Praxis daemon started[/] (pid {proc.pid})\n"
            f"[dim]logs: {log_path}[/]"
        )
    else:
        console.print(
            f"[red]✗ Daemon failed to start.[/]  Check {log_path}"
        )


@daemon.command("stop")
def daemon_stop() -> None:
    """Stop the running daemon."""
    pid = _daemon_pid()
    if not pid:
        console.print("[dim]No daemon running.[/]")
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as e:
        raise click.ClickException(f"Failed to stop pid {pid}: {e}")
    # Wait for it to exit.
    for _ in range(20):
        if not _daemon_pid():
            break
        time.sleep(0.2)
    console.print(f"[green]✓ Stopped daemon (pid {pid}).[/]")


@daemon.command("status")
def daemon_status() -> None:
    """Show daemon health + connectivity."""
    pid = _daemon_pid()
    if not pid:
        console.print("[dim]Daemon: stopped[/]")
        return
    try:
        r = asyncio.run(_socket_call("ping"))
        alive = r.get("status") == "success"
    except Exception:
        alive = False
    console.print(f"Daemon: [green]running[/] (pid {pid})" if alive
                  else f"Daemon: [yellow]pid {pid} present but socket not answering[/]")


# ---------------------------------------------------------------------------
# Filesystem verbs (via socket → praxis:local principal)
# ---------------------------------------------------------------------------


@main.command()
@click.argument("query")
@click.option("--path", "paths", multiple=True, help="Dir(s) to search (repeatable)")
@click.option("--ext", default="", help="Extension filter, e.g. pdf")
@click.option("--limit", default=10, help="Max results")
def search(query: str, paths: tuple[str, ...], ext: str, limit: int) -> None:
    """Find files by name (the local RAG)."""
    r = asyncio.run(_socket_call("fs.search", {
        "query": query,
        "paths": list(paths),
        "ext": ext,
        "limit": limit,
    }))
    if not r.get("ok"):
        _print_fs_result(r)
        return
    hits = r["result"]["hits"]
    if not hits:
        console.print("[dim]No matches.[/]")
        return
    table = Table(box=box.SIMPLE)
    table.add_column("score", justify="right", style="cyan")
    table.add_column("path")
    for h in hits:
        table.add_row(f"{h['score']:.1f}", h["path"])
    console.print(table)


@main.command()
@click.argument("path")
@click.option("--max-bytes", default=0, help="Cap the read size")
def read(path: str, max_bytes: int) -> None:
    """Read a file's contents (blocked on credential stores)."""
    r = asyncio.run(_socket_call("fs.read", {"paths": [path], "max_bytes": max_bytes}))
    if not r.get("ok"):
        _print_fs_result(r)
        return
    res = r["result"]
    if res.get("truncated"):
        console.print(f"[dim](truncated to {len(res['bytes'])} bytes)[/]")
    console.print(res["bytes"])


@main.command()
@click.argument("paths", nargs=-1, required=True)
def delete(paths: tuple[str, ...]) -> None:
    """Delete file(s) — staged to trash, recoverable for 24h."""
    r = asyncio.run(_socket_call("fs.delete", {"paths": list(paths)}))
    _print_fs_result(r)
    if r.get("ok"):
        for t in r.get("trashed_paths", []):
            console.print(f"  [dim]staged: {t}[/]")


@main.group()
def trash() -> None:
    """Inspect / restore the staged trash."""
    pass


@trash.command("list")
def trash_list() -> None:
    """List staged (deleted-but-recoverable) files."""
    from praxis.filesystem.trash import StagedTrash

    st = StagedTrash(trash_dir=STATE_DIR / "trash")
    entries = st.list_entries()
    if not entries:
        console.print("[dim]Trash is empty.[/]")
        return
    table = Table(box=box.SIMPLE)
    table.add_column("id", style="cyan")
    table.add_column("original path")
    table.add_column("staged", style="dim")
    for e in entries:
        staged_ago = time.time() - e.staged_at
        table.add_row(e.entry_id, e.original_path, f"{staged_ago/60:.0f}m ago")
    console.print(table)


@trash.command("restore")
@click.argument("entry_id")
def trash_restore(entry_id: str) -> None:
    """Restore a staged file to its original location."""
    from praxis.filesystem.trash import StagedTrash

    st = StagedTrash(trash_dir=STATE_DIR / "trash")
    try:
        restored = st.restore(entry_id)
        console.print(f"[green]✓ Restored[/] {restored}")
    except Exception as e:
        raise click.ClickException(str(e))


# ---------------------------------------------------------------------------
# ask — the offline LLM path
# ---------------------------------------------------------------------------


@main.command()
@click.argument("text")
@click.option("--path", "roots", multiple=True, help="Default search dirs")
@click.option("--model", default="", help="Ollama model (default llama3.2:3b)")
@click.option("--yes", is_flag=True, help="Auto-approve tool calls (TESTING)")
def ask(text: str, roots: tuple[str, ...], model: str, yes: bool) -> None:
    """Ask Praxis in plain language — local LLM plans, guardrail runs it.

    Works fully offline via Ollama.  Every tool call the model proposes
    still passes through the policy engine + approval flow.
    """
    asyncio.run(_ask_impl(text, list(roots), model, yes))


async def _ask_impl(text: str, roots: list[str], model: str, yes: bool) -> None:
    from praxis.approval import (
        ApprovalCoordinator,
        AutoApproveNotifier,
        NullAuthenticator,
    )
    from praxis.filesystem import (
        FSExecutor,
        FSPolicyEngine,
        StagedTrash,
        pick_default_backend,
    )
    from praxis.kill_switch import get_kill_switch
    from praxis.llm import LLMRegistry, OllamaBackend
    from praxis.orchestrator import Orchestrator
    from praxis.principal import Principal

    # Check Ollama first for a friendly error.
    ob = OllamaBackend(default_model=model or "llama3.2:3b")
    if not await ob.is_available():
        console.print(
            "[red]Ollama is not running.[/]\n"
            "Install from [cyan]https://ollama.com[/], then:\n"
            "  ollama pull llama3.2:3b\n"
            "  ollama serve   (or just open the Ollama app)\n"
        )
        return

    # In-process executor for the CLI (praxis:local principal).
    notifier = AutoApproveNotifier() if yes else _cli_notifier()
    executor = FSExecutor(
        policy=FSPolicyEngine(),
        approvals=ApprovalCoordinator(
            notifier=notifier,
            authenticator=NullAuthenticator(),
        ),
        trash=StagedTrash(trash_dir=STATE_DIR / "trash"),
        kill_switch=get_kill_switch(),
        search_backend=pick_default_backend(),
    )
    orch = Orchestrator(
        executor=executor,
        llm=LLMRegistry([ob]),
        model=model,
    )

    default_roots = roots or [str(Path.home() / "Documents"),
                              str(Path.home() / "Downloads"),
                              str(Path.home() / "Desktop")]

    console.print(f"[dim]Thinking (local model)…[/]")
    outcome = await orch.ask(
        user_text=text,
        principal=Principal.local(),
        default_search_roots=default_roots,
    )

    if outcome.error:
        console.print(f"[red]{outcome.error}[/]")
        return

    if outcome.steps:
        console.print("\n[bold]Actions taken:[/]")
        for s in outcome.steps:
            icon = "✓" if s.result.ok else "✗"
            color = "green" if s.result.ok else "red"
            console.print(f"  [{color}]{icon}[/] {s.summary()}")

    console.print(
        Panel(outcome.answer or "(no answer)",
              title=f"Praxis ({outcome.llm_backend or 'local'})",
              border_style="cyan")
    )


def _cli_notifier():
    """A notifier that prompts the user in the terminal for approvals."""
    from praxis.approval import ApprovalStatus

    class _TerminalNotifier:
        async def prompt(self, request) -> "ApprovalStatus":
            console.print(
                f"\n[yellow]⏸ Approval needed[/] — {request.summary}\n"
                f"  blast radius: {request.blast_radius}"
            )
            answer = click.confirm("  Approve?", default=False)
            return ApprovalStatus.APPROVED if answer else ApprovalStatus.DENIED

    return _TerminalNotifier()


# ---------------------------------------------------------------------------
# guard — the core: evaluate an AGENT action against the guardrail
# ---------------------------------------------------------------------------


@main.command()
@click.argument("action_type")
@click.option("--url", default="", help="URL for a browser action")
@click.option("--text", "element_text", default="", help="Element text, e.g. 'Pay Now'")
@click.option("--selector", default="", help="CSS selector")
@click.option("--policy", default="finance-safe",
              help="Browser policy preset: finance-safe / readonly / permissive")
@click.option("--as-agent", "agent", default="",
              help="Evaluate as an external agent (e.g. openclaw). Empty = legacy/no-principal.")
def guard(action_type: str, url: str, element_text: str, selector: str,
          policy: str, agent: str) -> None:
    """Evaluate an AGENT browser action against the guardrail.

    This is the core of Praxis. Shows exactly what the policy engine
    decides — ALLOW / BLOCK / REQUIRE_APPROVAL — for a browser action
    an AI agent wants to take.

    \b
    Examples:
        praxis guard navigate --url https://bank.com/dashboard
        praxis guard click --text "Pay Now" --url https://bank.com
        praxis guard click --text "Pay Now" --as-agent openclaw
    """
    from praxis.policy.engine import (
        ActionEvent, ActionType, PolicyEngine,
        create_finance_safe_policy, create_readonly_policy,
        create_permissive_policy,
    )

    presets = {
        "finance-safe": create_finance_safe_policy,
        "readonly": create_readonly_policy,
        "permissive": create_permissive_policy,
    }
    if policy not in presets:
        raise click.ClickException(
            f"Unknown policy {policy!r}. Choose: {', '.join(presets)}"
        )

    try:
        at = ActionType(action_type)
    except ValueError:
        raise click.ClickException(
            f"Unknown action_type {action_type!r}. "
            f"Valid: {[a.value for a in ActionType if a.value != 'filesystem']}"
        )

    engine = PolicyEngine()
    engine.load_policy(presets[policy]())

    principal = None
    if agent:
        from praxis.principal import Principal
        principal = Principal.agent(agent)

    event = ActionEvent(
        action_type=at,
        url=url,
        element_text=element_text,
        selector=selector,
        principal=principal,
    )
    decision = engine.evaluate(event)

    dec = decision.decision.value
    color = {"allow": "green", "block": "red",
             "require_approval": "yellow", "log_only": "blue"}.get(dec, "white")
    icon = {"allow": "✓", "block": "✗",
            "require_approval": "⏸", "log_only": "📝"}.get(dec, "?")

    who = f"agent:{agent}" if agent else "(no principal / legacy)"
    console.print(Panel.fit(
        f"[bold]{icon} {dec.upper()}[/]\n\n"
        f"action:   {action_type}\n"
        f"who:      {who}\n"
        f"policy:   {policy}\n"
        f"risk:     {decision.risk_level.value}\n"
        f"rule:     {decision.matched_rule or '(none)'}\n"
        f"reason:   {decision.reason or '(default)'}",
        border_style=color,
        title="Guardrail decision",
    ))


# ---------------------------------------------------------------------------
# evidence
# ---------------------------------------------------------------------------


@main.command()
@click.option("--limit", default=20, help="Max records to show")
def evidence(limit: int) -> None:
    """Show the hash-chained audit log of recent actions."""
    ev_dir = STATE_DIR / "evidence"
    if not ev_dir.exists():
        console.print("[dim]No evidence yet.[/]")
        return
    # Find the most recent session dir.
    sessions = sorted(
        [d for d in ev_dir.iterdir() if d.is_dir() and d.name.startswith("ses_")],
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )
    if not sessions:
        console.print("[dim]No evidence sessions.[/]")
        return
    jsonl = sessions[0] / "evidence.jsonl"
    if not jsonl.exists():
        console.print("[dim]Latest session has no records.[/]")
        return

    rows = []
    for line in jsonl.read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    rows = rows[-limit:]

    table = Table(title=f"Evidence — {sessions[0].name}", box=box.SIMPLE)
    table.add_column("#", justify="right", style="dim")
    table.add_column("principal", style="cyan")
    table.add_column("tier")
    table.add_column("action")
    table.add_column("decision")
    table.add_column("rule", style="dim")
    for r in rows:
        dec = r.get("decision", "")
        dcolor = {"allow": "green", "block": "red",
                  "require_approval": "yellow"}.get(dec, "white")
        table.add_row(
            str(r.get("sequence", "")),
            r.get("principal", "") or "(none)",
            r.get("tier", "") or "-",
            r.get("selector", "") or r.get("action_type", ""),
            f"[{dcolor}]{dec}[/]",
            r.get("matched_rule", ""),
        )
    console.print(table)
    console.print(f"[dim]Session dir: {sessions[0]}[/]")


# ---------------------------------------------------------------------------
# Client integration — enable/disable Praxis in on-device AI tools
# ---------------------------------------------------------------------------


@main.command()
def clients() -> None:
    """List on-device AI tools and whether Praxis is enabled in each."""
    from praxis.integrations import detect_clients

    statuses = detect_clients()
    table = Table(title="On-device AI tools", box=box.ROUNDED)
    table.add_column("Tool", style="cyan")
    table.add_column("Installed")
    table.add_column("Praxis")
    table.add_column("Config", style="dim")
    for s in statuses:
        installed = "[green]yes[/]" if s.installed else "[dim]no[/]"
        if not s.installed:
            praxis = "[dim]—[/]"
        elif s.enabled:
            praxis = "[green]● enabled[/]"
        else:
            praxis = "[yellow]○ disabled[/]"
        table.add_row(s.client.display_name, installed, praxis, str(s.client.config_path))
    console.print(table)
    console.print(
        "\n[dim]Enable with:  praxis enable <tool>   (e.g. praxis enable codex)\n"
        "Disable with: praxis disable <tool>\n"
        "Do all detected tools: praxis install[/]"
    )


def _client_keys() -> list[str]:
    from praxis.integrations import KNOWN_CLIENTS
    return [c.key for c in KNOWN_CLIENTS]


@main.command()
@click.argument("tool")
@click.option("--allow-writes", is_flag=True,
              help="Let agents create/write files (auto-approves). Default: reads only.")
@click.option("--path", "roots", multiple=True, help="Search roots (repeatable)")
def enable(tool: str, allow_writes: bool, roots: tuple[str, ...]) -> None:
    """Enable Praxis in an on-device AI tool (codex, claude-desktop, cursor, windsurf)."""
    from praxis.integrations import build_server_spec, get_client

    client = get_client(tool)
    if client is None:
        raise click.ClickException(
            f"Unknown tool {tool!r}. Options: {', '.join(_client_keys())}"
        )
    if not client.is_installed():
        console.print(
            f"[yellow]{client.display_name} doesn't appear to be installed.[/] "
            "Enabling anyway (config will be created)."
        )
    spec = build_server_spec(
        agent_name=client.key,
        search_roots=list(roots) or None,
        state_dir=STATE_DIR,
        allow_writes=allow_writes,
    )
    client.enable(spec)
    console.print(
        f"[green]✓ Praxis enabled in {client.display_name}.[/]\n"
        f"[dim]config: {client.config_path}[/]\n"
        f"[dim]mode: {'read+write (auto-approve)' if allow_writes else 'read-only (safe default)'}[/]\n\n"
        f"[bold]Restart {client.display_name} for it to take effect.[/]"
    )


@main.command()
@click.argument("tool")
def disable(tool: str) -> None:
    """Disable Praxis in an on-device AI tool."""
    from praxis.integrations import get_client

    client = get_client(tool)
    if client is None:
        raise click.ClickException(
            f"Unknown tool {tool!r}. Options: {', '.join(_client_keys())}"
        )
    changed = client.disable()
    if changed:
        console.print(
            f"[green]✓ Praxis disabled in {client.display_name}.[/]\n"
            f"[bold]Restart {client.display_name} for it to take effect.[/]"
        )
    else:
        console.print(f"[dim]Praxis was not enabled in {client.display_name}.[/]")


@main.command()
@click.option("--allow-writes", is_flag=True,
              help="Let agents create/write files. Default: reads only.")
def install(allow_writes: bool) -> None:
    """One-shot: enable Praxis in every detected on-device AI tool."""
    from praxis.integrations import build_server_spec, detect_clients

    statuses = detect_clients(installed_only=True)
    if not statuses:
        console.print(
            "[yellow]No supported AI tools detected.[/]\n"
            "Supported: ChatGPT/Codex Desktop, Claude Desktop, Cursor, Windsurf.\n"
            "Install one, then run `praxis install` again."
        )
        return

    console.print("[bold]Enabling Praxis in detected AI tools:[/]\n")
    for s in statuses:
        spec = build_server_spec(
            agent_name=s.client.key,
            state_dir=STATE_DIR,
            allow_writes=allow_writes,
        )
        try:
            s.client.enable(spec)
            console.print(f"  [green]✓[/] {s.client.display_name}")
        except Exception as e:
            console.print(f"  [red]✗[/] {s.client.display_name}: {e}")

    console.print(
        f"\n[dim]mode: {'read+write' if allow_writes else 'read-only (safe default)'}[/]\n"
        "[bold]Restart each tool for Praxis to take effect.[/]\n"
        "Check status anytime with:  praxis clients"
    )


if __name__ == "__main__":
    main()
