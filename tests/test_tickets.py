"""The ground truth must be in the capture, and the scorer must tell good answers from bad."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from ticketbench import baseline
from ticketbench.prompt import system_prompt, user_prompt
from ticketbench.score import asserts, parse_answer, score
from ticketbench.tickets import LABELS, TICKETS, Built, build


@pytest.fixture(scope="module")
def built(tmp_path_factory) -> dict[str, Built]:
    out = tmp_path_factory.mktemp("caps")
    return {t.id: build(t, out) for t in TICKETS}


def tshark_frames(path: Path, display_filter: str) -> list[int]:
    out = subprocess.run(
        [
            "tshark",
            "-n",
            "-r",
            str(path),
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [int(n) for n in out.split()]


def reference(b: Built, **override) -> dict:
    answer = {
        "root_cause": b.ticket.root_cause,
        "subscriber": b.ticket.subscriber,
        "evidence_frames": sorted(b.key_frames),
        "summary": "",
        "customer_reply": b.ticket.reference_reply,
    }
    return {**answer, **override}


def test_ids_unique_and_labels_known():
    assert len({t.id for t in TICKETS}) == len(TICKETS)
    assert len({t.public_name for t in TICKETS}) == len(TICKETS)
    assert all(t.root_cause in LABELS for t in TICKETS)
    assert all(label in system_prompt() for label in LABELS)


@pytest.mark.parametrize("ticket", TICKETS, ids=lambda t: t.id)
def test_ground_truth_is_in_the_capture(ticket, built):
    b = built[ticket.id]
    assert b.frame_count == len(tshark_frames(b.path, "frame"))
    assert set(ticket.key_tags) <= set(b.tagged)
    for check in ticket.checks:
        matches = tshark_frames(b.path, check.display_filter)
        if check.tag is None:
            assert matches == [], check.display_filter
        else:
            assert b.tagged[check.tag] in matches, (check.tag, check.display_filter)


@pytest.mark.parametrize("ticket", TICKETS, ids=lambda t: t.id)
def test_reference_answer_passes(ticket, built):
    s = score(built[ticket.id], reference(built[ticket.id]))
    assert s.passed, s


def test_wrong_label_fails(built):
    b = built["t05-cannot-attach-but-it-did"]
    s = score(b, reference(b, root_cause="subscriber_unknown"))
    assert not s.root_cause_ok and not s.passed


def test_nonexistent_frame_is_a_hallucination(built):
    b = built["t01-new-sim-never-attaches"]
    s = score(b, reference(b, evidence_frames=[10, 412]))
    assert s.nonexistent == [412] and s.grounded and not s.passed


def test_ungrounded_evidence_fails(built):
    b = built["t01-new-sim-never-attaches"]
    s = score(b, reference(b, evidence_frames=[1, 2]))  # another SIM's healthy attach
    assert not s.grounded and not s.passed


def test_agreeing_with_the_customer_misdiagnosis_fails(built):
    b = built["t01-new-sim-never-attaches"]
    reply = "The SIM is not provisioned, and the SIM is faulty, so we will send a replacement."
    s = score(b, reference(b, customer_reply=reply))
    assert len(s.reply_forbidden) == 2 and not s.passed


def test_parse_answer_takes_the_last_json_block():
    text = (
        'First guess:\n```json\n{"root_cause": "unknown_apn"}\n```\n'
        'Final:\n```json\n{"root_cause": "credit_limit_reached", "evidence_frames": [12]}\n```'
    )
    assert parse_answer(text)["root_cause"] == "credit_limit_reached"
    assert parse_answer('done. {"root_cause": "no_fault_in_capture"}')["root_cause"] == (
        "no_fault_in_capture"
    )
    assert parse_answer("no json here") is None


def test_unparsed_answer_fails(built):
    s = score(built["t03-data-stopped-midday"], parse_answer("I think it is the OCS."))
    assert not s.parsed and not s.passed


def test_capsight_baseline(built):
    got = {tid: baseline.answer(b)["root_cause"] for tid, b in built.items()}
    assert got == {t.id: t.root_cause for t in TICKETS}
    # capsight finds no fault for t05's subscriber but has nothing to cite for it
    t05 = built["t05-cannot-attach-but-it-did"]
    assert not score(t05, baseline.answer(t05), score_reply=False).grounded


def test_scores_serialise(built):
    b = built["t02-connected-no-data"]
    json.dumps(score(b, reference(b)).as_dict())


def test_negated_forbidden_phrase_is_allowed(built):
    b = built["t02-connected-no-data"]
    ok = "There is no need to change the APN. Replies cannot route back because NAT is missing."
    assert score(b, reference(b, customer_reply=ok)).passed
    bad = "Please change the APN to internet; routing looks fine."
    assert not score(b, reference(b, customer_reply=bad)).passed
    assert asserts(r"change the apn", "Done, so change the APN now")
    assert not asserts(r"change the apn", "You don't have to change the APN")


@pytest.mark.parametrize("ticket", TICKETS, ids=lambda t: t.id)
def test_agent_never_sees_the_ticket_id_or_label(ticket, built):
    b = built[ticket.id]
    seen = user_prompt(b) + b.path.name
    assert ticket.id not in seen and ticket.root_cause not in seen
