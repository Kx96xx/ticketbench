# Results

## 2026-11-27: all 10 tickets, Claude Sonnet 5.5

One run per ticket and arm through `claude -p` (Claude subscription), no built-in tools, only
the arm's MCP server. [Results and transcripts](../results/).

| Arm | Pass | Root cause | Grounded | Hallucinated frames | Replies OK | Mean calls | Mean time | Cost (USD) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| capsight 0.3 alone, no AI | 7/10 | 8/10 | 8/10 | 0 | - | - | - | 0 |
| agent + plain tshark | 10/10 | 10/10 | 10/10 | 0 of 57 cited | 10/10 | 3.2 | 20 s | 0.39 |
| agent + tshark-mcp | 10/10 | 10/10 | 10/10 | 0 of 46 cited | 10/10 | 3.1 | 31 s | 0.60 |

What it says:

- The five harder tickets still do not separate the arms on correctness. Both agents
  followed the session conflict across GTP-C and PFCP (t06), found the policy refusal behind
  the gateway's "system failure" (t07) and the user plane that stopped answering (t08), and
  said honestly that a capture without the subscriber cannot show the cause (t09) instead of
  calling it "no fault". Every reply corrected the customer's guess (unstable roaming
  partner, broken gateway, changed APN, bad SIM keys).
- They differ in cost and time. tshark-mcp cost 1.5 times as much and took 1.5 times as
  long: its tool definitions put about 34k input tokens into every turn, against about 3k for
  one `run_tshark` tool. Where a specialised tool fits the question it answers in one call
  (`roaming_attach_check` on t10, `trace_subscriber` on t01 and t04); on the session conflict
  it took 6 calls and 90 s against 3 calls and 42 s with plain tshark.
- capsight 0.3 alone misses the two tickets that need more than one message: it sees only
  "system failure" codes in t06 and calls t09 "no fault". The session chain on capsight's
  main branch names the conflict in t06; the baseline is rerun when 0.4 is released.
- Next tickets have to be harder in other ways: thousands of frames with background noise,
  two faults at once, a misleading time in the ticket, and a cause that needs a spec detail
  rather than a code lookup.

Scoring note: the run's own scorer failed two plain-tshark replies that were correct on
reading ("both sessions ask for the same fixed IP address"; "no activity for SIM ...117",
where "they attached normally" was about the other three SIMs). The patterns were fixed,
all 20 replies went into `tests/replies.json` with their hand verdicts, and the saved
answers were rescored without another model call. Rows keep `passed_as_run`.

## 2026-11-26: first run, 5 tickets, Claude Sonnet 5.5

One run per ticket through `claude -p` (Claude subscription), no built-in tools, only the
arm's MCP server. [Results and transcripts](../results/).

| Arm | Pass | Root cause | Grounded | Hallucinated frames | Replies OK | Mean calls | Cost (USD) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| capsight alone, no AI | 4/5 | 5/5 | 4/5 | 0 | - | - | 0 |
| agent + plain tshark | 5/5 | 5/5 | 5/5 | 0 of 22 cited | 5/5 | 3.2 | 0.14 |
| agent + tshark-mcp | 5/5 | 5/5 | 5/5 | 0 of 25 cited | 5/5 | 2.6 | 0.33 |

What it says:

- These five tickets are too easy to separate the arms: both agents found every root cause,
  cited only real frames and ignored the distractors, including the trap where another SIM
  fails loudly. Every reply also corrected the customer's wrong guess (faulty SIM, wrong
  APN, outage). The next tickets have to be harder: nested causes, two procedures to join,
  captures that cannot show the cause.
- tshark-mcp used fewer calls but cost 2.4 times as much: its 34 tool definitions add about
  25k input tokens to every turn. On easy tickets one `run_tshark` tool is enough.
- capsight alone gets every root cause but has nothing to cite when the answer is "no fault
  for this subscriber".

Scoring note: the run's own scorer failed two tshark-mcp replies that were correct on
reading ("the HSS doesn't have IMSI ... provisioned", "SIM ...109 attaches normally ... all
succeed"). The two patterns were widened, every reply from the run went into
`tests/replies.json` with its hand verdict, and the saved answers were rescored without
another model call (`ticketbench rescore`). Rows keep `passed_as_run`.
