"""ticketbench list | build DIR | baseline | prompt TICKET"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from ticketbench import baseline
from ticketbench.prompt import system_prompt, user_prompt
from ticketbench.score import score, summarise
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


if __name__ == "__main__":
    raise SystemExit(main())
