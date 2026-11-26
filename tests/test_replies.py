"""Real agent replies (judged by hand) and known-bad ones: the reply checks must agree.

When a model run finds a reply the checks misjudge, the reply goes in replies.json with the
right verdict and the pattern is fixed, so a pattern change never silently flips an old verdict.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ticketbench.score import score
from ticketbench.tickets import TICKETS, build

REPLIES = json.loads((Path(__file__).parent / "replies.json").read_text())
CASES = [
    (tid, verdict, reply)
    for tid, sets in REPLIES.items()
    for verdict in ("good", "bad")
    for reply in sets[verdict]
]


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    out = tmp_path_factory.mktemp("caps")
    return {t.id: build(t, out) for t in TICKETS}


def test_every_ticket_has_good_and_bad_replies():
    assert set(REPLIES) == {t.id for t in TICKETS}
    assert all(sets["good"] and sets["bad"] for sets in REPLIES.values())


@pytest.mark.parametrize("tid,verdict,reply", CASES)
def test_reply_check_agrees_with_the_hand_verdict(tid, verdict, reply, built):
    b = built[tid]
    answer = {
        "root_cause": b.ticket.root_cause,
        "evidence_frames": sorted(b.key_frames),
        "customer_reply": reply,
    }
    s = score(b, answer)
    assert s.reply_ok == (verdict == "good"), (s.reply_missing, s.reply_forbidden)
