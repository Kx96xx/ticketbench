"""The agent arms: each ticket is one ``claude -p`` session with only the arm's MCP server.

The session gets no built-in tools (no shell, no file reads), no settings, no other MCP
servers and nothing persisted, and runs in an empty directory next to the capture, so the
only way to the answer is the capture. It runs on the logged-in Claude subscription
(ANTHROPIC_API_KEY is removed from its environment).

    ticketbench run --arm tshark-only --arm tshark-mcp --model claude-sonnet-5-5 \\
        --max-runs 10 --max-usd 5
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ticketbench.prompt import system_prompt, user_prompt
from ticketbench.score import parse_answer, score
from ticketbench.tickets import Ticket, build

SERVER = "pcap"  # tools appear to the model as mcp__pcap__<tool>
TIMEOUT_S = 900

ARMS: dict[str, list[str]] = {
    "tshark-only": [sys.executable, "-m", "ticketbench.tshark_only"],
    "tshark-mcp": [sys.executable, "-m", "tshark_mcp.server"],
}


def claude_argv(model: str | None, config: str, max_turns: int) -> list[str]:
    argv = [
        shutil.which("claude") or "claude",
        "-p",
        "--system-prompt",
        system_prompt(),
        "--mcp-config",
        config,
        "--strict-mcp-config",
        "--tools",
        "",
        "--allowedTools",
        f"mcp__{SERVER}",
        "--output-format",
        "stream-json",
        "--verbose",
        "--no-session-persistence",
        "--setting-sources",
        "",
        "--max-turns",
        str(max_turns),
    ]
    return argv + (["--model", model] if model else [])


@dataclass
class Session:
    calls: list[dict[str, Any]] = field(default_factory=list)
    text: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    turns: int = 0
    cost_usd: float | None = None
    problems: list[str] = field(default_factory=list)


def parse_transcript(lines: list[str]) -> Session:
    s = Session()
    prefix = f"mcp__{SERVER}__"
    uses: dict[str, dict[str, Any]] = {}
    ended = False
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        kind = event.get("type")
        if kind in ("assistant", "user"):
            for block in event.get("message", {}).get("content") or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_use":
                    name = block.get("name", "")
                    call = {"tool": name.removeprefix(prefix), "args": block.get("input") or {}}
                    uses[block.get("id", "")] = call
                    s.calls.append(call)
                elif block.get("type") == "tool_result" and block.get("tool_use_id") in uses:
                    uses[block["tool_use_id"]]["is_error"] = bool(block.get("is_error"))
        elif kind == "result":
            ended = True
            s.text = event.get("result") or ""
            u = event.get("usage") or {}
            s.input_tokens = sum(
                int(u.get(k) or 0)
                for k in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
            )
            s.output_tokens = int(u.get("output_tokens") or 0)
            s.turns = int(event.get("num_turns") or 0)
            s.cost_usd = event.get("total_cost_usd")
            if event.get("is_error") or event.get("subtype", "success") != "success":
                s.problems.append(f"session ended with {event.get('subtype') or 'an error'}")
    if not ended:
        s.problems.append("session gave no result")
    return s


INIT_KEEP = ("type", "subtype", "model", "tools", "mcp_servers", "claude_code_version")
DROP_EVENTS = {"rate_limit_event"}  # account usage, not part of the run
DROP_KEYS = {"session_id", "uuid", "cwd", "original_cwd", "memory_paths"}
TEMP_CAPTURES = re.compile(r"[^\"\s]*/tb-[A-Za-z0-9_]+/captures")


def sanitise(lines: list[str]) -> list[str]:
    """A transcript safe to publish: no account usage, local paths or session ids."""
    out = []
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("type") in DROP_EVENTS:
            continue
        if event.get("type") == "system" and event.get("subtype") == "init":
            event = {k: event[k] for k in INIT_KEEP if k in event}
        else:
            event = {k: v for k, v in event.items() if k not in DROP_KEYS}
        out.append(TEMP_CAPTURES.sub("/captures", json.dumps(event)))
    return out


def run_one(
    ticket: Ticket, arm: str, model: str | None, max_turns: int, transcripts: Path | None
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="tb-") as tmp:
        caps = Path(tmp) / "captures"
        caps.mkdir()
        built = build(ticket, caps)
        work = Path(tmp) / "work"  # empty cwd: nothing to read but the capture
        work.mkdir()
        config = Path(tmp) / "mcp.json"
        command = [*ARMS[arm], "--allow-dir", str(caps)]
        config.write_text(
            json.dumps({"mcpServers": {SERVER: {"command": command[0], "args": command[1:]}}})
        )
        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        started = time.monotonic()
        try:
            out = subprocess.run(
                claude_argv(model, str(config), max_turns),
                input=user_prompt(built),
                capture_output=True,
                text=True,
                cwd=work,
                env=env,
                timeout=TIMEOUT_S,
            )
            lines = out.stdout.splitlines()
        except subprocess.TimeoutExpired as exc:
            lines = (exc.stdout or b"").decode(errors="replace").splitlines()
        seconds = round(time.monotonic() - started, 2)
        session = parse_transcript(lines)
        if transcripts is not None:
            transcripts.mkdir(parents=True, exist_ok=True)
            (transcripts / f"{arm}--{ticket.id}.jsonl").write_text(
                "\n".join(sanitise(lines)) + "\n"
            )
        result = score(built, parse_answer(session.text))
    return {
        "arm": arm,
        "ticket": ticket.id,
        **result.as_dict(),
        "calls": len(session.calls),
        "tools": [c["tool"] for c in session.calls],
        "tool_errors": sum(bool(c.get("is_error")) for c in session.calls),
        "input_tokens": session.input_tokens,
        "output_tokens": session.output_tokens,
        "turns": session.turns,
        "cost_usd": session.cost_usd,
        "seconds": seconds,
        "problems": session.problems,
        "answer": session.text,
    }


def summarise_rows(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for arm in dict.fromkeys(r["arm"] for r in rows):
        rs = [r for r in rows if r["arm"] == arm]
        out[arm] = {
            "tickets": len(rs),
            "passed": sum(r["passed"] for r in rs),
            "root_cause_correct": sum(r["root_cause_ok"] for r in rs),
            "grounded": sum(r["grounded"] for r in rs),
            "frames_cited": sum(len(r["cited"]) for r in rs),
            "frames_hallucinated": sum(len(r["nonexistent"]) for r in rs),
            "replies_ok": sum(not r["reply_missing"] and not r["reply_forbidden"] for r in rs),
            "mean_calls": round(sum(r["calls"] for r in rs) / len(rs), 2),
            "cost_usd": round(sum(r["cost_usd"] or 0 for r in rs), 4),
            "mean_seconds": round(sum(r["seconds"] for r in rs) / len(rs), 1),
        }
    return out


def require_claude() -> None:
    if not shutil.which("claude"):
        raise SystemExit("the agent arms need the claude CLI on PATH, logged in")
