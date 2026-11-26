"""The agent driver, without calling a model."""

from __future__ import annotations

import json

from ticketbench.agent import claude_argv, parse_transcript, sanitise, summarise_rows


def _lines(*events: dict) -> list[str]:
    return [json.dumps(e) for e in events]


def test_parse_transcript_reads_calls_answer_and_usage():
    lines = _lines(
        {"type": "system", "subtype": "init", "tools": ["mcp__pcap__run_tshark"]},
        {
            "type": "assistant",
            "message": {
                "content": [
                    {"type": "tool_use", "id": "a", "name": "mcp__pcap__run_tshark", "input": {}}
                ]
            },
        },
        {
            "type": "user",
            "message": {"content": [{"type": "tool_result", "tool_use_id": "a", "is_error": True}]},
        },
        {
            "type": "result",
            "subtype": "success",
            "result": '```json\n{"root_cause": "unknown_apn"}\n```',
            "usage": {"input_tokens": 10, "cache_read_input_tokens": 90, "output_tokens": 7},
            "num_turns": 2,
            "total_cost_usd": 0.01,
        },
    )
    s = parse_transcript(["not json", *lines])
    assert s.calls == [{"tool": "run_tshark", "args": {}, "is_error": True}]
    assert s.input_tokens == 100 and s.output_tokens == 7 and s.turns == 2
    assert s.cost_usd == 0.01 and s.problems == []
    assert "unknown_apn" in s.text


def test_parse_transcript_reports_a_session_with_no_result():
    assert parse_transcript([]).problems == ["session gave no result"]
    s = parse_transcript(_lines({"type": "result", "subtype": "error_max_turns", "result": ""}))
    assert s.problems == ["session ended with error_max_turns"]


def test_the_session_gets_no_builtin_tools():
    argv = claude_argv("m", "/tmp/mcp.json", 5)
    assert argv[argv.index("--tools") + 1] == ""
    assert "--strict-mcp-config" in argv and "--no-session-persistence" in argv


def test_summary_counts_per_arm():
    row = {
        "arm": "a",
        "passed": True,
        "root_cause_ok": True,
        "grounded": True,
        "cited": [1, 99],
        "nonexistent": [99],
        "reply_missing": [],
        "reply_forbidden": [],
        "calls": 3,
        "cost_usd": 0.5,
        "seconds": 10.0,
    }
    summary = summarise_rows([row, {**row, "passed": False, "cost_usd": None}])["a"]
    assert summary["passed"] == 1 and summary["frames_hallucinated"] == 2
    assert summary["cost_usd"] == 0.5 and summary["mean_calls"] == 3


def test_sanitise_drops_account_and_local_details():
    lines = _lines(
        {
            "type": "system",
            "subtype": "init",
            "model": "m",
            "cwd": "/Users/x/w",
            "memory_paths": {},
        },
        {"type": "rate_limit_event", "rate_limit_info": {"utilization": 0.9}},
        {
            "type": "assistant",
            "session_id": "s",
            "message": {
                "content": [{"input": {"path": "/var/folders/ab/T/tb-x1_y/captures/t01.pcap"}}]
            },
        },
    )
    out = "\n".join(sanitise(lines))
    assert "/Users/" not in out and "utilization" not in out and "session_id" not in out
    assert '"/captures/t01.pcap"' in out and '"model": "m"' in out
