"""ticketbench list | build DIR | baseline | prompt TICKET | run --arm ... --model ..."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

from ticketbench import agent, baseline
from ticketbench.prompt import system_prompt, user_prompt
from ticketbench.score import parse_answer, score, summarise
from ticketbench.tickets import TICKETS, build, by_id


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ticketbench")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="ticket ids and ground-truth labels")
    b = sub.add_parser("build", help="write every ticket's capture into DIR")
    b.add_argument("dir", type=Path)
    sub.add_parser("baseline", help="score capsight on its own (no AI)")
    pr = sub.add_parser("prompt", help="print the system and user prompt for one ticket")
    pr.add_argument("ticket")
    r = sub.add_parser("run", help="run agent arms through claude -p (costs tokens)")
    r.add_argument("--arm", action="append", choices=sorted(agent.ARMS), required=True)
    r.add_argument("--model", required=True)
    r.add_argument("--only", action="append", help="ticket id (repeatable); default all")
    r.add_argument("--repeats", type=int, default=1)
    r.add_argument("--max-turns", type=int, default=20)
    r.add_argument("--max-runs", type=int, required=True, help="refuse a larger plan")
    r.add_argument("--max-usd", type=float, required=True, help="stop once reported cost passes")
    r.add_argument("--out", type=Path, default=Path("results"))
    rs = sub.add_parser("rescore", help="score a results file again (no model call)")
    rs.add_argument("results", type=Path)
    args = p.parse_args(argv)

    if args.cmd == "list":
        for t in TICKETS:
            print(f"{t.id:34} {t.root_cause}")
        return 0
    if args.cmd == "build":
        args.dir.mkdir(parents=True, exist_ok=True)
        for t in TICKETS:
            built = build(t, args.dir)
            print(f"{built.path}  frames={built.frame_count}  key={sorted(built.key_frames)}")
        return 0
    if args.cmd == "run":
        return run(args)
    if args.cmd == "rescore":
        return rescore(args.results)
    with tempfile.TemporaryDirectory(prefix="ticketbench-") as tmp:
        if args.cmd == "prompt":
            built = build(by_id(args.ticket), Path(tmp))
            print(system_prompt(), "\n---\n", user_prompt(built, built.path.name))
            return 0
        scores = []
        for t in TICKETS:
            built = build(t, Path(tmp))
            s = score(built, baseline.answer(built), score_reply=False)
            scores.append(s)
            mark = "PASS" if s.passed else "FAIL"
            print(f"{mark}  {t.id:34} got {s.root_cause}, cited {s.cited}")
        json.dump(summarise(scores), sys.stdout, indent=1)
        print()
    return 0


def rescore(path: Path) -> int:
    """Score the saved answers with the current checks; keep the old verdicts alongside."""
    data = json.loads(path.read_text())
    changed = 0
    with tempfile.TemporaryDirectory(prefix="ticketbench-") as tmp:
        for row in data["rows"]:
            built = build(by_id(row["ticket"]), Path(tmp))
            new = score(built, parse_answer(row["answer"])).as_dict()
            if new["passed"] != row["passed"]:
                changed += 1
                print(f"{row['arm']:12} {row['ticket']:34} {row['passed']} -> {new['passed']}")
                row.setdefault("passed_as_run", row["passed"])
            row.update(new)
    data["summary"] = agent.summarise_rows(data["rows"])
    path.write_text(json.dumps(data, indent=1) + "\n")
    json.dump(data["summary"], sys.stdout, indent=1)
    print(f"\n{changed} verdicts changed; {path}")
    return 0


def run(args: argparse.Namespace) -> int:
    agent.require_claude()
    tickets = [by_id(t) for t in args.only] if args.only else list(TICKETS)
    plan = [(t, arm) for _ in range(args.repeats) for t in tickets for arm in args.arm]
    if len(plan) > args.max_runs:
        raise SystemExit(f"plan is {len(plan)} runs, more than --max-runs {args.max_runs}")
    date = time.strftime("%Y-%m-%d", time.gmtime())
    stem = f"{date}-{args.model}"
    transcripts = args.out / "transcripts" / stem
    rows: list[dict] = []
    skipped = 0
    for i, (t, arm) in enumerate(plan, 1):
        spent = sum(r["cost_usd"] or 0 for r in rows)
        if spent >= args.max_usd:
            skipped = len(plan) - i + 1
            print(f"stopping: ${spent:.2f} spent, cap ${args.max_usd}", file=sys.stderr)
            break
        row = agent.run_one(t, arm, args.model, args.max_turns, transcripts)
        rows.append(row)
        mark = "PASS" if row["passed"] else "FAIL"
        print(
            f"{mark}  {arm:12} {t.id:34} {row['root_cause']}  cited={row['cited']}  "
            f"calls={row['calls']}  ${row['cost_usd'] or 0:.3f}  {row['seconds']}s"
            + (f"  problems={row['problems']}" if row["problems"] else ""),
            flush=True,
        )
    summary = agent.summarise_rows(rows)
    meta = {
        "date": date,
        "driver": "claude-code",
        "model": args.model,
        "arms": args.arm,
        "tickets": [t.id for t in tickets],
        "repeats": args.repeats,
        "planned_runs": len(plan),
        "skipped": skipped,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / f"{stem}.json"
    path.write_text(json.dumps({"meta": meta, "summary": summary, "rows": rows}, indent=1) + "\n")
    json.dump(summary, sys.stdout, indent=1)
    print(f"\n{path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
