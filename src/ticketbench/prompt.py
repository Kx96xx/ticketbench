"""What the agent is told. The same text for every arm; only the tools differ."""

from __future__ import annotations

from ticketbench.tickets import LABELS, Built

SYSTEM = """You are a support engineer for a mobile network operator. A customer opened the \
ticket below and a packet capture from the core network is attached. Find out what is wrong \
for the customer's subscriber, using only what the capture shows, and write the reply we \
send them.

Use your tools to read the capture. Do not assume anything the capture does not show. Cite \
frame numbers only from tool output.

End your reply with one JSON object in a ```json block:

{{"root_cause": "<one label from the list>", "subscriber": "<IMSI>", \
"evidence_frames": [<frame numbers that show the root cause>], \
"summary": "<what the capture shows, two sentences>", \
"customer_reply": "<the reply to the customer, plain language, under 120 words>"}}

Root cause labels:
{labels}
"""


def system_prompt() -> str:
    labels = "\n".join(f"- {k}: {v}" for k, v in LABELS.items())
    return SYSTEM.format(labels=labels)


def user_prompt(built: Built, capture_path: str | None = None) -> str:
    return (
        f"Ticket {built.ticket.public_name}:\n\n{built.ticket.ticket}\n\n"
        f"Capture: {capture_path or built.path}"
    )
