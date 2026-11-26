"""Score one answer to one ticket. Deterministic: no model grades another model.

The agent ends its reply with a JSON object:

    {"root_cause": "<label>", "subscriber": "<IMSI>", "evidence_frames": [12, 13],
     "summary": "<what the capture shows>", "customer_reply": "<what we send the customer>"}

Scored on:

- root cause: the label matches the ground truth;
- evidence: every cited frame exists in the capture (a frame number beyond the capture is a
  hallucination), and at least one cited frame is a key frame of the ground truth (grounded).
  A ticket whose truth is an absence (the subscriber is not in the capture) has no key
  frames; there, any answer without invented frames is grounded;
- reply: the customer reply matches every required pattern and asserts no forbidden one (the
  forbidden ones are what a wrong or careless reply says: "the SIM is faulty", "change the
  APN"; "no need to change the APN" is not asserting it).

A ticket passes when all three hold. An arm without a customer reply (capsight on its own)
is scored on root cause and evidence only.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ticketbench.tickets import LABELS, Built

_FENCED = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.S)
_NEGATION = re.compile(r"\b(no|not|never|without|nothing)\b|n't\b", re.I)
_CLAUSE_END = re.compile(r"[.!?;,:\n]")
NEGATION_WINDOW = 30  # characters before a forbidden phrase, within its clause


def asserts(pattern: str, text: str) -> bool:
    """The text says the forbidden thing, not "no need to <thing>" or "<thing> is not needed"."""
    for m in re.finditer(pattern, text, re.I | re.S):
        before = text[max(0, m.start() - NEGATION_WINDOW) : m.start()]
        before = _CLAUSE_END.split(before)[-1]
        if not _NEGATION.search(before):
            return True
    return False


def parse_answer(text: str) -> dict[str, Any] | None:
    """The last JSON object in the reply that has a root_cause (fenced or bare)."""
    candidates = [m.group(1) for m in _FENCED.finditer(text)]
    if not candidates:
        candidates = [text[i:] for i, c in enumerate(text) if c == "{"]
    decoder = json.JSONDecoder()
    for chunk in reversed(candidates):
        try:
            obj, _ = decoder.raw_decode(chunk.strip())
        except ValueError:
            continue
        if isinstance(obj, dict) and "root_cause" in obj:
            return obj
    return None


def _frames(value: Any) -> list[int]:
    out = []
    for v in value if isinstance(value, list) else [value]:
        try:
            out.append(int(v))
        except (TypeError, ValueError):
            continue
    return out


@dataclass
class Score:
    ticket: str
    parsed: bool
    root_cause: str | None
    root_cause_ok: bool
    cited: list[int] = field(default_factory=list)
    nonexistent: list[int] = field(default_factory=list)
    grounded: bool = False
    reply_missing: list[str] = field(default_factory=list)  # required patterns not matched
    reply_forbidden: list[str] = field(default_factory=list)  # forbidden patterns matched
    reply_scored: bool = True

    @property
    def reply_ok(self) -> bool:
        return not self.reply_missing and not self.reply_forbidden

    @property
    def passed(self) -> bool:
        return (
            self.root_cause_ok
            and self.grounded
            and not self.nonexistent
            and (self.reply_ok or not self.reply_scored)
        )

    def as_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items()}
        d["passed"] = self.passed
        return d


def score(built: Built, answer: dict[str, Any] | None, score_reply: bool = True) -> Score:
    t = built.ticket
    if answer is None:
        return Score(
            t.id,
            False,
            None,
            False,
            reply_scored=score_reply,
            reply_missing=list(t.reply_must) if score_reply else [],
        )
    label = str(answer.get("root_cause", "")).strip()
    cited = _frames(answer.get("evidence_frames", []))
    s = Score(
        ticket=t.id,
        parsed=True,
        root_cause=label if label in LABELS else f"(not a label) {label}",
        root_cause_ok=label == t.root_cause,
        cited=cited,
        nonexistent=[n for n in cited if not 1 <= n <= built.frame_count],
        grounded=bool(set(cited) & built.key_frames) if built.key_frames else True,
        reply_scored=score_reply,
    )
    if score_reply:
        reply = str(answer.get("customer_reply", ""))
        s.reply_missing = [p for p in t.reply_must if not re.search(p, reply, re.I | re.S)]
        s.reply_forbidden = [p for p in t.reply_must_not if asserts(p, reply)]
    return s


def summarise(scores: list[Score]) -> dict[str, Any]:
    n = len(scores)
    cited = sum(len(s.cited) for s in scores)
    return {
        "tickets": n,
        "passed": sum(s.passed for s in scores),
        "root_cause_correct": sum(s.root_cause_ok for s in scores),
        "grounded": sum(s.grounded for s in scores),
        "frames_cited": cited,
        "frames_hallucinated": sum(len(s.nonexistent) for s in scores),
        "replies_ok": sum(s.reply_ok for s in scores if s.reply_scored),
        "unparsed": sum(not s.parsed for s in scores),
    }
