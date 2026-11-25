# Design

## The question

A customer opens a ticket ("the SIM is faulty", "your network is down") and attaches a packet
capture from the core. Can an AI agent find the real root cause, cite evidence that exists,
and write a reply that is right and does not repeat the customer's wrong guess?

## How this differs from PcapBench

[tshark-mcp's PcapBench](https://github.com/Kx96xx/tshark-mcp/blob/main/docs/BENCHMARK.md)
asks fact questions with one exact answer ("which Result-Code did the AIA carry?") and
measures whether its tools help a model find the fact. ticketbench asks the support
engineer's question: "what is wrong, and what do we tell the customer?" Nobody tells the agent
which protocol, subscriber procedure or field to look at, and the ticket often points the
wrong way.

## A ticket

- the customer's text, as the agent sees it;
- a synthetic capture built for it (`pcapgen.py`, copied from capsight). Frames that prove the
  root cause are tagged, so their numbers come from the build;
- the ground truth: one root-cause label from a fixed list (in the prompt), the key frames,
  and display filters that prove the truth is in the capture (CI runs them through tshark);
- reply checks: patterns the customer reply must contain, and patterns it must not assert
  (the customer's misdiagnosis, a needless SIM swap);
- distractors: other subscribers, healthy procedures, failures that are not the ticket's.

Target mix for about 40 tickets:

| Third | What | Example |
| --- | --- | --- |
| Rules can answer | one clear failure for the subscriber | AIA 5001 user unknown |
| Reasoning needed | the customer's guess is wrong, the failure is in a nested field, or two procedures must be joined | MSCC 4012 inside a CCA with Result-Code 2001 |
| Traps | no fault for this subscriber, or the capture cannot show the cause | another IMSI fails loudly; a one-direction capture |

## Scoring (deterministic, no model grades a model)

- **Root cause**: the label matches.
- **Grounded**: at least one cited frame is a key frame.
- **Hallucinated frames**: cited frame numbers that do not exist in the capture, counted per
  run. Reported on their own, because an invented frame number is worse than a wrong label.
- **Reply**: every required pattern matches, no forbidden pattern is asserted ("no need to
  change the APN" does not assert "change the APN").
- **Pass**: all of the above.

## Arms

| Arm | Status |
| --- | --- |
| capsight alone, no AI (rules, findings filtered to the subscriber, mapped to a label) | done |
| agent + one `run_tshark` tool | planned |
| agent + tshark-mcp | planned |
| agent + tshark-mcp + capsight's JSON findings as a tool | planned |

Each model run states a cap on runs and cost, records every tool call, tokens and cost, and
commits the transcripts with the results. One run per ticket is noisy; report repeats.

## Rules

- Synthetic captures only: test-network IMSIs (001/01), RFC 5737 addresses, example.org.
  No real capture, operator, customer or partner data, ever.
- Built at a steady pace: about five tickets a week, results published when an arm runs on
  at least 15 tickets.

## Known limits

- The tickets and captures are written by capsight's author with capsight's packet builder,
  which favours capsight on the first third. The other two thirds exist to measure what rules
  cannot do.
- Reply checks are regular expressions: coarse, but repeatable and cheap. Ambiguous replies
  are fixed by tightening the pattern and adding a test, not by a model judge.
- Synthetic captures are small and clean. Busy captures with thousands of subscribers are a
  later step.
