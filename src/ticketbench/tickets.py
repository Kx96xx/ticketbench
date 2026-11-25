"""The tickets: what the customer wrote, the capture that goes with it, and the ground truth.

Each ticket builds its own synthetic capture. Frames that prove the root cause carry a tag, so
their frame numbers come from the build, never from hand counting. Every capture also holds
traffic that does not matter (other subscribers, healthy procedures), because a real capture
does, and some of it fails on purpose: a good answer ignores what the ticket is not about.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ticketbench import pcapgen as g

T0 = 1_795_183_200.0  # 2026-11-20 14:00:00 UTC
IMSI = "0010100000001{:02d}".format

# The answer must pick one of these. The list is in the prompt, so the agent is never
# asked to guess our vocabulary.
LABELS: dict[str, str] = {
    "subscriber_unknown": "The SIM's IMSI is not provisioned in the HSS/UDM.",
    "authentication_failure": "Authentication fails: wrong keys on the SIM or in the HSS.",
    "roaming_not_allowed": "The subscriber may not use the visited network.",
    "unknown_apn": "The device asks for an APN/DNN the network does not know or allow.",
    "pdn_type_not_allowed": "The requested PDN type (IPv4/IPv6/IPv4v6) is not allowed.",
    "policy_rejected": "The PCRF/PCF rejects or removes the session's policy (Gx/N7).",
    "credit_limit_reached": "The charging system (OCS) stops data: no balance or quota left.",
    "user_plane_no_return_path": "The session is up but replies cannot come back "
    "(missing NAT or return route on SGi/N6).",
    "peer_not_answering": "A network element does not answer requests (timeouts).",
    "no_fault_in_capture": "The capture shows this subscriber's procedures working.",
    "capture_insufficient": "The capture cannot show the cause (wrong place, wrong time, "
    "or the relevant traffic is missing).",
}


@dataclass(frozen=True)
class Frame:
    time: float
    data: bytes
    tag: str | None = None  # names a frame that the ground truth points at


@dataclass(frozen=True)
class Check:
    """A display filter that must match the tagged frame (or, with tag None, no frame)."""

    tag: str | None
    display_filter: str


@dataclass(frozen=True)
class Ticket:
    id: str
    ticket: str  # the customer's words, as the agent sees them
    subscriber: str
    root_cause: str
    frames: Callable[[], list[Frame]]
    key_tags: tuple[str, ...]  # citing any of these frames grounds the answer
    checks: tuple[Check, ...]  # prove the ground truth is in the capture
    reply_must: tuple[str, ...] = ()  # regexes the customer reply must match
    reply_must_not: tuple[str, ...] = ()  # regexes it must not match
    reference_reply: str = ""  # one reply that passes; tests the regexes
    notes: str = ""  # what makes it hard: distractors, traps

    @property
    def public_name(self) -> str:
        """What the agent sees (the id's tail would give the answer away): "t05"."""
        return self.id.split("-")[0]

    def __post_init__(self) -> None:
        if self.root_cause not in LABELS:
            raise ValueError(f"{self.id}: unknown label {self.root_cause}")


@dataclass(frozen=True)
class Built:
    ticket: Ticket
    path: Path
    frame_count: int
    tagged: dict[str, int] = field(default_factory=dict)  # tag -> frame number

    @property
    def key_frames(self) -> set[int]:
        return {self.tagged[t] for t in self.ticket.key_tags}


def build(ticket: Ticket, out: Path) -> Built:
    frames = sorted(ticket.frames(), key=lambda f: f.time)
    tagged = {f.tag: n for n, f in enumerate(frames, 1) if f.tag}
    path = g.write_pcap(out / f"{ticket.public_name}.pcap", [(f.time, f.data) for f in frames])
    return Built(ticket, path, len(frames), tagged)


# ---- small procedure builders ---------------------------------------------------------------

AIR, ULR = 318, 316
CS_REQ, CS_RESP = 32, 33
GTP_ACCEPTED, GTP_UNKNOWN_APN = 16, 78


class _S6a:
    """MME <-> HSS over one TCP connection; hop-by-hop ids are unique per capture."""

    def __init__(self) -> None:
        self.flow = g.TcpFlow(g.HOST_A, g.HOST_B, 40001, 3868)
        self.hbh = 0x200

    def exchange(
        self,
        t: float,
        cmd: int,
        imsi: str,
        experimental: int | None = None,
        tags: tuple[str | None, str | None] = (None, None),
    ) -> list[Frame]:
        self.hbh += 2
        answer = (
            g.s6a_answer(cmd, self.hbh, experimental=experimental)
            if experimental
            else g.s6a_answer(cmd, self.hbh)
        )
        return [
            Frame(t, self.flow.frame(True, g.s6a_request(cmd, self.hbh, imsi)), tags[0]),
            Frame(t + 0.012, self.flow.frame(False, answer), tags[1]),
        ]

    def attach(self, t: float, imsi: str) -> list[Frame]:
        return self.exchange(t, AIR, imsi) + self.exchange(t + 0.4, ULR, imsi)


class _S11:
    def __init__(self) -> None:
        self.seq = 0x40

    def create_session(
        self,
        t: float,
        imsi: str,
        apn: str,
        cause: int = GTP_ACCEPTED,
        tags: tuple[str | None, str | None] = (None, None),
    ) -> list[Frame]:
        self.seq += 1
        request = g.gtpv2(CS_REQ, self.seq, [g.ie_imsi(imsi), g.ie_apn(apn), g.ie_rat_type()])
        response = g.gtpv2(CS_RESP, self.seq, [g.ie_cause(cause)], teid=0x1000 + self.seq)
        return [
            Frame(t, g.gtpv2_frame(True, request), tags[0]),
            Frame(t + 0.03, g.gtpv2_frame(False, response), tags[1]),
        ]


# ---- the tickets ------------------------------------------------------------------------------


def _t01() -> list[Frame]:
    s6a = _S6a()
    return [
        *s6a.attach(T0, IMSI(1)),
        *s6a.attach(T0 + 2.0, IMSI(2)),
        *s6a.exchange(T0 + 5.0, AIR, IMSI(3), experimental=5001, tags=("air", "aia")),
        *s6a.exchange(T0 + 15.0, AIR, IMSI(3), experimental=5001),  # the device retries
        *s6a.attach(T0 + 40.0, IMSI(1)),  # a healthy re-attach later on
    ]


T01 = Ticket(
    id="t01-new-sim-never-attaches",
    ticket=(
        "Hi, we activated three new SIMs for our trackers this morning. Two of them came "
        f"online right away but the third one (IMSI {IMSI(3)}) never connects, it just "
        "searches. We think the SIM is faulty. Can you send us a replacement? Capture from "
        "your side attached."
    ),
    subscriber=IMSI(3),
    root_cause="subscriber_unknown",
    frames=_t01,
    key_tags=("aia",),
    checks=(
        Check("air", f'diameter.User-Name == "{IMSI(3)}"'),
        Check("aia", "diameter.Experimental-Result-Code == 5001"),
    ),
    reply_must=(r"not (yet )?(provisioned|registered|known|found|activated|set up)",),
    reply_must_not=(
        r"(sim|card) (is|was|looks) (faulty|defective|damaged|broken)",
        r"send (you )?(a )?replacement",
    ),
    reference_reply=(
        "The SIM itself is fine: it reaches our network and asks to authenticate, but our "
        "subscriber database answers that this IMSI is not provisioned (user unknown). The "
        "activation did not complete for it. We are fixing the provisioning; no replacement "
        "is needed."
    ),
    notes="Two other SIMs attach normally in the same capture. The customer's own diagnosis "
    "(faulty SIM) is wrong; a reply that agrees with it fails.",
)


def _t02() -> list[Frame]:
    s11 = _S11()
    frames = [*s11.create_session(T0, IMSI(4), "internet", tags=(None, "session_up"))]
    t = T0 + 3.0
    for i in range(5):
        ping = g.icmp_echo(g.UE_IP, g.DN_IP)
        frames.append(Frame(t + i, g.gtpu_frame(True, ping), "tunnel_up" if i == 0 else None))
        frames.append(Frame(t + i + 0.0002, g.plain_ip_frame(ping), "n6_out" if i == 0 else None))
    return frames


T02 = Ticket(
    id="t02-connected-no-data",
    ticket=(
        "Our test phone shows full bars and the data icon, but nothing loads and ping to the "
        f"internet fails. We restarted it twice. IMSI {IMSI(4)}. Is our APN setting wrong?"
    ),
    subscriber=IMSI(4),
    root_cause="user_plane_no_return_path",
    frames=_t02,
    key_tags=("n6_out", "tunnel_up"),
    checks=(
        Check("session_up", f"gtpv2.cause == {GTP_ACCEPTED}"),
        Check("tunnel_up", "gtp && ip.src == 10.45.0.5 && icmp.type == 8"),
        Check("n6_out", "!gtp && ip.src == 10.45.0.5 && icmp.type == 8"),
        Check(None, "icmp.type == 0"),  # no reply anywhere
    ),
    reply_must=(r"(nat|address translation|masquerad|return route|route back|routing)",),
    reply_must_not=(
        r"(change|update|correct|fix) (the |your )?apn",
        r"(replace|reprovision|re-provision) (the )?sim",
    ),
    reference_reply=(
        "Your session is up and the APN is correct: we see your pings arrive and leave towards "
        "the internet, but they leave with the device's private address 10.45.0.5, so replies "
        "cannot route back. The address translation (NAT) for the device pool is missing on "
        "our gateway; we are restoring it. No change is needed on the phone."
    ),
    notes="The session setup succeeds; the fault is only visible in the user plane. The "
    "customer suggests an APN problem, which the accepted Create Session rules out.",
)


def _t03() -> list[Frame]:
    gy = g.TcpFlow(g.HOST_A, g.HOST_B, 40002, 3868)
    frames: list[Frame] = []
    hbh = 0x700

    def pair(t: float, imsi: str, req_type: int, answer_mscc: bytes, tags=(None, None)):
        nonlocal hbh
        hbh += 2
        frames.append(
            Frame(
                t,
                gy.frame(True, g.ccr(hbh, req_type=req_type, imsi=imsi, extra=[g.mscc(10)])),
                tags[0],
            )
        )
        frames.append(
            Frame(
                t + 0.02,
                gy.frame(False, g.cca(hbh, req_type=req_type, extra=[answer_mscc])),
                tags[1],
            )
        )

    pair(T0, IMSI(5), g.CC_INITIAL, g.mscc(10, result=2001))
    pair(T0 + 1, IMSI(6), g.CC_INITIAL, g.mscc(10, result=2001))
    for i in range(1, 4):
        pair(T0 + 60 * i, IMSI(6), g.CC_UPDATE, g.mscc(10, result=2001))
    pair(T0 + 90, IMSI(5), g.CC_UPDATE, g.mscc(10, result=2001))
    pair(
        T0 + 150,
        IMSI(5),
        g.CC_UPDATE,
        g.mscc(10, result=4012, final_action=0),
        tags=("ccr", "cca_4012"),
    )
    return frames


T03 = Ticket(
    id="t03-data-stopped-midday",
    ticket=(
        f"Device {IMSI(5)} worked fine all month and then stopped passing data around "
        "14:02 UTC today. It still shows as connected. Nothing changed on our side. Is "
        "there an outage?"
    ),
    subscriber=IMSI(5),
    root_cause="credit_limit_reached",
    frames=_t03,
    key_tags=("cca_4012",),
    checks=(
        Check("ccr", f'e212.imsi == "{IMSI(5)}"'),
        Check("cca_4012", "diameter.Result-Code == 4012"),
    ),
    reply_must=(r"(balance|quota|credit|top.?up|data (plan|allowance|limit)|spending limit)",),
    reply_must_not=(r"(there is|we have|due to|caused by) an? (network |charging )?outage",),
    reference_reply=(
        "There is no network fault: your device's session is up, but at 14:02 UTC our "
        "charging system stopped granting data because the credit limit on this SIM was "
        "reached. Topping up the balance or raising the data limit restores data."
    ),
    notes="Another subscriber's updates keep succeeding, so it is not a charging outage. "
    "The overall Result-Code is 2001 (success); only the MSCC result inside says 4012.",
)


def _t04() -> list[Frame]:
    s11 = _S11()
    frames = []
    for i, t in enumerate((T0, T0 + 4, T0 + 9)):
        frames += s11.create_session(t, IMSI(8), "iot.example", tags=(None, None))
        frames += s11.create_session(
            t + 1.5,
            IMSI(7),
            "internet.wrong",
            cause=GTP_UNKNOWN_APN,
            tags=("cs_req", "cs_reject") if i == 0 else (None, None),
        )
    return frames


T04 = Ticket(
    id="t04-routers-no-data",
    ticket=(
        "Our new routers on your SIMs can't get data. The modem log says 'PDP context "
        f"activation failed'. Example IMSI {IMSI(7)}. Our older routers are fine. Your "
        "network must be having issues, please check urgently."
    ),
    subscriber=IMSI(7),
    root_cause="unknown_apn",
    frames=_t04,
    key_tags=("cs_reject", "cs_req"),
    checks=(
        Check("cs_req", 'gtpv2.apn == "internet.wrong"'),
        Check("cs_reject", f"gtpv2.cause == {GTP_UNKNOWN_APN}"),
    ),
    reply_must=(r"\bapn\b", r"internet\.wrong"),
    reply_must_not=(r"network (is|was) (down|having issues)",),
    reference_reply=(
        "The network is working: your older routers connect with APN iot.example. The new "
        "routers ask for APN internet.wrong, which our network does not know, so the session "
        "is rejected (missing or unknown APN). Set the APN to iot.example on the new routers."
    ),
    notes="Another IMSI on the right APN succeeds alongside each failure. The best replies "
    "name the APN the working devices use.",
)


def _t05() -> list[Frame]:
    s6a, s11 = _S6a(), _S11()
    return [
        *s6a.attach(T0, IMSI(9)),
        *s11.create_session(T0 + 1.0, IMSI(9), "iot.example", tags=(None, "cs_accept")),
        *s6a.exchange(T0 + 2.0, AIR, IMSI(10), experimental=5001),
        *s6a.exchange(T0 + 12.0, AIR, IMSI(10), experimental=5001),
        *s6a.exchange(T0 + 30.0, AIR, IMSI(10), experimental=5001),
    ]


T05 = Ticket(
    id="t05-cannot-attach-but-it-did",
    ticket=(
        f"SIM {IMSI(9)} cannot attach since this afternoon, please investigate. Attached "
        "is a capture from your core taken while the customer was testing."
    ),
    subscriber=IMSI(9),
    root_cause="no_fault_in_capture",
    frames=_t05,
    key_tags=("cs_accept",),
    checks=(Check("cs_accept", f"gtpv2.cause == {GTP_ACCEPTED}"),),
    reply_must=(
        r"(attach(ed)?|connect(ed)?|session).{0,80}(success|accepted|worked|working|"
        r"completed)|(success|accepted|completed).{0,80}(attach|session)",
    ),
    reply_must_not=(r"(your|this) (sim|imsi|subscriber) is not provisioned",),
    reference_reply=(
        "In this capture the SIM attached successfully: authentication, location update and "
        "the data session were all accepted. To find the failure we need a capture from the "
        "moment the device fails, with the time and the device's error message."
    ),
    notes="A different IMSI fails three times with user unknown (5001) in the same capture. "
    "An agent that reports the loudest failure instead of the ticket's subscriber fails.",
)

TICKETS: tuple[Ticket, ...] = (T01, T02, T03, T04, T05)


def by_id(ticket_id: str) -> Ticket:
    for t in TICKETS:
        if t.id == ticket_id:
            return t
    raise KeyError(ticket_id)
