"""The no-AI arm: capsight's rules on their own.

capsight reports findings, not tickets, so this arm needs two small steps an agent does on
its own: keep the findings about the ticket's subscriber, and turn the most severe one into a
label. No finding about the subscriber means "no_fault_in_capture". There is no customer
reply, so the reply is not scored for this arm.
"""

from __future__ import annotations

import re
from typing import Any

from capsight.engine import analyze
from capsight.model import Finding

from ticketbench.tickets import Built

# (rule id prefix, verdict pattern or "", label): first match wins.
RULE_LABELS: tuple[tuple[str, str, str], ...] = (
    ("diameter.result", r"USER_UNKNOWN|UNKNOWN_SUBSCRIPTION", "subscriber_unknown"),
    ("diameter.result", r"ROAMING_NOT_ALLOWED|RAT_NOT_ALLOWED", "roaming_not_allowed"),
    ("diameter.result", r"AUTHENTICATION|AUTHORIZATION_REJECTED", "authentication_failure"),
    ("diameter.unanswered", "", "peer_not_answering"),
    ("gtpv2.cause", r"APN", "unknown_apn"),
    ("gtpv2.pdn_type", "", "pdn_type_not_allowed"),
    ("gtpv2.unanswered", "", "peer_not_answering"),
    ("gtpu.one_way", "", "user_plane_no_return_path"),
    ("pcc.credit", "", "credit_limit_reached"),
    ("pcc.", "", "policy_rejected"),
    ("roaming.", "", "roaming_not_allowed"),
    ("map.unanswered", "", "peer_not_answering"),
    ("map.error", r"Unknown subscriber|unknownSubscriber", "subscriber_unknown"),
    ("map.error", r"Roaming not allowed|roamingNotAllowed", "roaming_not_allowed"),
    ("pfcp.unanswered", "", "peer_not_answering"),
    ("nas.emm.reject", r"#(7|8|11|12|13|14|15)\b|not allowed", "roaming_not_allowed"),
    ("nas5g.mm.reject", r"not allowed", "roaming_not_allowed"),
    ("nas.esm.reject", r"APN|#27\b", "unknown_apn"),
    ("nas5g.sm.reject", r"DNN", "unknown_apn"),
)
SEVERITY_ORDER = {"failure": 0, "warning": 1, "info": 2}


def label(finding: Finding) -> str | None:
    for prefix, pattern, name in RULE_LABELS:
        if finding.rule_id.startswith(prefix) and (
            not pattern or re.search(pattern, finding.verdict, re.I)
        ):
            return name
    return None


def about(finding: Finding, subscriber: str) -> bool:
    # A finding with no subscriber (e.g. a user-plane flow keyed by address) may be about anyone.
    return not finding.subscribers or subscriber in finding.subscribers


def answer(built: Built) -> dict[str, Any]:
    findings = [
        f
        for f in analyze(built.path).findings
        if f.severity != "info" and about(f, built.ticket.subscriber)
    ]
    findings.sort(key=lambda f: SEVERITY_ORDER.get(str(f.severity), 3))
    for f in findings:
        name = label(f)
        if name:
            return {
                "root_cause": name,
                "evidence_frames": list(f.evidence),
                "summary": f.verdict,
                "customer_reply": "",
            }
    return {
        "root_cause": "no_fault_in_capture",
        "evidence_frames": [],
        "summary": "No finding about this subscriber.",
        "customer_reply": "",
    }
