# Results

Tickets 6-10 (added 2026-11-26) have not been run by an agent yet. capsight 0.3 alone gets
3 of the 5 root causes; it misses the session conflict (a chain across GTP-C and PFCP) and
the capture that does not contain the subscriber. The label list gained
`ue_address_conflict`, so later runs see a slightly longer prompt than the first one.

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
