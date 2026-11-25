# ticketbench

Can an AI agent diagnose a mobile connectivity ticket from a packet capture?

Each ticket is what a customer actually writes ("the SIM is faulty, send a replacement"),
plus a synthetic core-network capture built for it. The agent reads the capture with its
tools and answers with a root cause, the frames that prove it, and the reply we would send
the customer. Scoring is deterministic:

- **root cause**: one label from a fixed list;
- **grounded**: the cited frames include the ones that prove the cause;
- **hallucinated frames**: cited frame numbers that do not exist;
- **reply**: says what it must, and does not repeat the customer's wrong guess.

Captures hold distractors on purpose: other subscribers failing, healthy procedures, a ticket
whose subscriber has no fault at all.

Work in progress: 5 tickets so far, aiming for about 40. See [docs/DESIGN.md](docs/DESIGN.md).

## Try it

Needs Python 3.11+ and tshark.

```sh
uv sync
uv run ticketbench list               # tickets and ground-truth labels
uv run ticketbench build captures/    # write the captures
uv run ticketbench prompt t04-routers-no-data
uv run ticketbench baseline           # capsight's rules alone, no AI
uv run pytest                         # the ground truth is in every capture (via tshark)
```

## Arms

capsight alone (no AI) is the baseline. Next: an agent with plain tshark, with
[tshark-mcp](https://github.com/Kx96xx/tshark-mcp), and with tshark-mcp plus
[capsight](https://github.com/Kx96xx/capsight).

Every capture is synthetic: test-network IMSIs (001/01), RFC 5737 addresses, example.org.

Built with Claude Code. MIT licence.
