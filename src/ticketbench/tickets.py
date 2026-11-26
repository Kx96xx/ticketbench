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
    "ue_address_conflict": "Two sessions need the same UE IP address (for example one static "
    "address on two APNs), so one is refused or torn down.",
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
    # "not provisioned", "doesn't have IMSI ... provisioned", "user unknown"
    reply_must=(
        r"(\bnot\b|n't|never).{0,50}(provisioned|registered|activated|set up|known|found)"
        r"|\bunknown\b|unprovisioned",
    ),
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
        # "attached successfully", "attaches normally ... all succeed", "was accepted"
        r"(attach\w*|connect\w*|session)\b.{0,80}(succe\w*|accepted|work\w*|normal\w*|"
        r"complet\w*)|(succe\w*|accepted|complet\w*).{0,80}(attach|session)",
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


PFCP_EST_REQ, PFCP_EST_RESP, PFCP_REPORT_REQ, PFCP_REPORT_RESP = 50, 51, 56, 57
PFCP_ACCEPTED, PFCP_SYSTEM_FAILURE = 1, 77
GTP_SYSTEM_FAILURE = 72
PCRF_HOST = bytes([192, 0, 2, 70])
STATIC_IP = bytes([100, 64, 10, 20])  # RFC 6598 shared space, stands in for a static address


class _Gateway:
    """A PGW: GTP-C from the SGW, PFCP to its UPF, Gx to its PCRF."""

    def __init__(self) -> None:
        self.gtp_seq = 0x300
        self.pfcp_seq = 10
        self.seid = 0x9000
        self.gx = g.TcpFlow(g.HOST_B, PCRF_HOST, 40010, 3868)
        self.hbh = 0x900

    def _next_pfcp(self) -> int:
        self.pfcp_seq += 1
        return self.pfcp_seq

    def csr(self, t: float, imsi: str, apn: str, visited: str | None = None, tag=None) -> Frame:
        self.gtp_seq += 1
        ies = [g.ie_imsi(imsi), g.ie_apn(apn), g.ie_rat_type()]
        if visited:  # over S8 from a visited network's SGW
            ies += [g.ie_serving_network("001", visited), g.ie_fteid(g.S8_SGW_GTPC, self.gtp_seq)]
        return Frame(t, g.gtpv2_frame(True, g.gtpv2(CS_REQ, self.gtp_seq, ies)), tag)

    def csr_answer(self, t: float, cause: int, tag=None) -> Frame:
        resp = g.gtpv2(CS_RESP, self.gtp_seq, [g.ie_cause(cause)], teid=0x2000 + self.gtp_seq)
        return Frame(t, g.gtpv2_frame(False, resp), tag)

    def establish(self, t: float, ue_ip: bytes, tag=None) -> tuple[Frame, int, int]:
        """PFCP Session Establishment Request; returns the frame, its sequence and CP SEID."""
        seq, self.seid = self._next_pfcp(), self.seid + 1
        ies = [g.pfcp_fseid(self.seid), g.pfcp_create_pdr(ue_ip, "iot.example.org")]
        frame = g.pfcp_frame(True, g.pfcp(PFCP_EST_REQ, seq, seid=0, ies=ies))
        return Frame(t, frame, tag), seq, self.seid

    def establish_answer(self, t: float, seq: int, seid: int, cause: int, tag=None) -> Frame:
        return Frame(t, g.pfcp_frame(False, g.pfcp(PFCP_EST_RESP, seq, seid, cause)), tag)

    def deleted_by_up(self, t: float, seid: int, tag=None) -> list[Frame]:
        seq = self._next_pfcp()
        report = g.pfcp(PFCP_REPORT_REQ, seq, seid=seid, ies=list(g.PFCP_DELETED_BY_UP))
        return [
            Frame(t, g.pfcp_frame(False, report), tag),
            Frame(t + 0.004, g.pfcp_frame(True, g.pfcp(PFCP_REPORT_RESP, seq, 0x77, 1))),
        ]

    def gx_initial(self, t: float, imsi: str, apn: str, result: int = 2001, tag=None):
        self.hbh += 2
        ccr = g.ccr(self.hbh, app=g.GX_APP, req_type=g.CC_INITIAL, imsi=imsi, apn=apn)
        cca = g.cca(self.hbh, app=g.GX_APP, req_type=g.CC_INITIAL, result=result)
        return [
            Frame(t, self.gx.frame(True, ccr)),
            Frame(t + 0.01, self.gx.frame(False, cca), tag),
        ]


def _t06() -> list[Frame]:
    """Two APNs ask for one static address; each new session knocks the other out."""
    gw = _Gateway()
    frames: list[Frame] = []
    t = T0
    apns = ("iot.example", "data.example")
    req, seq, current = gw.establish(t + 0.05, STATIC_IP)
    frames += [
        gw.csr(t, IMSI(11), apns[0], visited="02"),
        req,
        gw.establish_answer(t + 0.051, seq, current, PFCP_ACCEPTED),
        gw.csr_answer(t + 0.06, GTP_ACCEPTED),
    ]
    for i in range(1, 7):
        t += 2.1
        apn = apns[i % 2]
        first = i == 1
        req, seq, seid = gw.establish(t + 0.05, STATIC_IP, "refused_req" if first else None)
        frames += [
            gw.csr(t, IMSI(11), apn, visited="02"),
            req,
            *gw.deleted_by_up(t + 0.0505, current, "deleted" if first else None),
            gw.establish_answer(
                t + 0.051, seq, seid, PFCP_SYSTEM_FAILURE, "refused" if first else None
            ),
            gw.csr_answer(t + 0.06, GTP_SYSTEM_FAILURE, "gtp_72" if first else None),
        ]
        retry_req, seq, current = gw.establish(t + 0.35, STATIC_IP)
        frames += [
            gw.csr(t + 0.3, IMSI(11), apn, visited="02"),
            retry_req,
            gw.establish_answer(t + 0.351, seq, current, PFCP_ACCEPTED),
            gw.csr_answer(t + 0.36, GTP_ACCEPTED),
        ]
    return frames


T06 = Ticket(
    id="t06-roaming-data-keeps-dropping",
    ticket=(
        f"Our trackers roaming abroad (IMSI {IMSI(11)} for example) connect, then lose "
        "data a few seconds later, over and over. The roaming partner's network must be "
        "unstable. Can you raise it with them?"
    ),
    subscriber=IMSI(11),
    root_cause="ue_address_conflict",
    frames=_t06,
    key_tags=("refused", "deleted", "refused_req", "gtp_72"),
    checks=(
        Check("refused", f"pfcp.cause == {PFCP_SYSTEM_FAILURE}"),
        Check("deleted", "pfcp.srreq_flags.psdbu == 1"),
        Check("refused_req", "pfcp.ue_ip_addr_ipv4 == 100.64.10.20"),
        Check("gtp_72", f"gtpv2.cause == {GTP_SYSTEM_FAILURE}"),
    ),
    reply_must=(
        r"(same|one|shared|single|identical) (static )?(ip|address)|(ip|address).{0,40}"
        r"\b(both|two)\b.{0,20}apns?",
        r"\bapns?\b",
    ),
    reply_must_not=(
        r"(roaming partner|visited network|partner's network) (is|was) (unstable|at fault|"
        r"the (cause|problem))",
        r"we (will|'ll) raise (it|this) with (them|the (roaming )?partner)",
    ),
    reference_reply=(
        "This is on our side, not the roaming partner's. Your tracker opens sessions on two "
        "APNs, iot.example and data.example, and both use the same static IP address. Our "
        "gateway cannot hold two sessions on one address, so each new session is refused and "
        "the other one is torn down, and the device reconnects in a loop. We will give each "
        "APN its own address, or you can set the trackers to use one APN."
    ),
    notes="Every message says 'system failure' (GTP 72, PFCP 77). Only the UPF's Session "
    "Report (session deleted by the UP function) and the shared UE address in both PFCP "
    "requests explain it. Retries succeed, so the customer sees flapping, not an outage.",
)


def _t07() -> list[Frame]:
    """The PCRF refuses the policy for the new plan; the PGW only says 'system failure'."""
    gw = _Gateway()
    frames: list[Frame] = []
    for i, t in enumerate((T0, T0 + 3, T0 + 6, T0 + 9)):
        ok_imsi, bad_imsi = IMSI(13), IMSI(12)
        frames += [
            gw.csr(t, ok_imsi, "fleet.example"),
            *gw.gx_initial(t + 0.02, ok_imsi, "fleet.example"),
            gw.csr_answer(t + 0.05, GTP_ACCEPTED),
        ]
        first = i == 0
        frames += [
            gw.csr(t + 1, bad_imsi, "fleet.example"),
            *gw.gx_initial(
                t + 1.02, bad_imsi, "fleet.example", result=5003, tag="cca" if first else None
            ),
            gw.csr_answer(t + 1.05, GTP_SYSTEM_FAILURE, "gtp_72" if first else None),
        ]
    return frames


T07 = Ticket(
    id="t07-new-plan-no-data",
    ticket=(
        "We moved some SIMs to the new Fleet Pro plan this morning and those lost data. "
        f"SIMs we did not move still work. Example of a moved SIM: {IMSI(12)}. Your NOC said "
        "the gateway reports 'system failure'. Is the gateway broken?"
    ),
    subscriber=IMSI(12),
    root_cause="policy_rejected",
    frames=_t07,
    key_tags=("cca",),
    checks=(
        Check("cca", "diameter.Result-Code == 5003"),
        Check("gtp_72", f"gtpv2.cause == {GTP_SYSTEM_FAILURE}"),
    ),
    reply_must=(r"(polic|pcrf|plan|rule|profile|authori[sz])",),
    reply_must_not=(r"gateway (is|was) (broken|faulty|down)", r"(replace|swap) (the )?sims?"),
    reference_reply=(
        "The gateway itself is fine: SIMs on the old plan get sessions from it. For the moved "
        "SIMs, our policy server refuses to authorise the data session (authorization "
        "rejected), and the gateway then reports a generic system failure. The Fleet Pro "
        "plan's policy is not set up correctly for these SIMs; we are fixing the plan "
        "configuration."
    ),
    notes="The GTP cause (72) points at the gateway. The reason is one hop away on Gx: CCA "
    "Result-Code 5003. Another SIM on the same APN keeps working.",
)


def _t08() -> list[Frame]:
    """The UPF stops answering PFCP; sessions fail after the gateway gives up."""
    gw = _Gateway()
    frames: list[Frame] = []
    req, seq, seid = gw.establish(T0 + 0.05, g.UE_IP)
    frames += [
        gw.csr(T0, IMSI(14), "iot.example"),
        req,
        gw.establish_answer(T0 + 0.051, seq, seid, PFCP_ACCEPTED),
        gw.csr_answer(T0 + 0.06, GTP_ACCEPTED),
    ]
    for n, (t, imsi) in enumerate(((T0 + 60, IMSI(15)), (T0 + 75, IMSI(16)), (T0 + 90, IMSI(15)))):
        req, seq, seid = gw.establish(t + 0.05, g.UE_IP, "unanswered" if n == 0 else None)
        frames += [gw.csr(t, imsi, "iot.example"), req]
        for k in (1, 2):  # the gateway retransmits, then gives up
            again = g.pfcp(PFCP_EST_REQ, seq, seid=0, ies=[g.pfcp_fseid(seid)])
            frames.append(Frame(t + 0.05 + k, g.pfcp_frame(True, again)))
        frames.append(gw.csr_answer(t + 3.1, GTP_SYSTEM_FAILURE, "gtp_72" if n == 0 else None))
    return frames


T08 = Ticket(
    id="t08-sessions-time-out",
    ticket=(
        "Since about 14:01 UTC none of our devices can start a data session. They wait a "
        f"few seconds and then fail. Example IMSI {IMSI(15)}. Did you change the APN "
        "settings?"
    ),
    subscriber=IMSI(15),
    root_cause="peer_not_answering",
    frames=_t08,
    key_tags=("unanswered",),
    checks=(
        Check("unanswered", f"pfcp.msg_type == {PFCP_EST_REQ}"),
        Check("gtp_72", f"gtpv2.cause == {GTP_SYSTEM_FAILURE}"),
        Check(None, f"pfcp.msg_type == {PFCP_EST_RESP} && frame.time_relative > 30"),
    ),
    reply_must=(
        r"(stopped|not|n't|never) (respond|answer)\w*|unresponsive|time[sd]? ?out|timeout"
        r"|no (response|answer)",
    ),
    reply_must_not=(
        r"(change|update|correct|fix) (the |your )?apn",
        r"(device|sim|apn) (is|was) (misconfigured|wrong|faulty)",
    ),
    reference_reply=(
        "Nothing changed in your APN settings. Since 14:01 UTC one of our core components, "
        "the user-plane function, stopped answering our gateway, so every new data session "
        "times out and fails after a few seconds. This affects all devices, not only yours. "
        "We are restoring it now."
    ),
    notes="The gateway answers with a vague 72 after 3 s. The reason is visible only in "
    "PFCP: Session Establishment requests retransmitted with no answer, for every "
    "subscriber after 14:01, while the session at 14:00 worked.",
)


def _t09() -> list[Frame]:
    """A healthy capture that never contains the ticket's subscriber."""
    s6a, s11 = _S6a(), _S11()
    frames: list[Frame] = []
    for i, imsi in enumerate((IMSI(18), IMSI(19), IMSI(20))):
        frames += s6a.attach(T0 + 5 * i, imsi)
        frames += s11.create_session(T0 + 5 * i + 1, imsi, "iot.example")
    return frames


T09 = Ticket(
    id="t09-subscriber-not-in-capture",
    ticket=(
        f"SIM {IMSI(17)} cannot attach. Here is a capture from your core from when the "
        "customer tried. What is wrong with the SIM?"
    ),
    subscriber=IMSI(17),
    root_cause="capture_insufficient",
    frames=_t09,
    key_tags=(),
    checks=(
        Check(None, f'e212.imsi == "{IMSI(17)}"'),
        Check(None, f'diameter.User-Name == "{IMSI(17)}"'),
    ),
    reply_must=(
        r"(not (appear|present|seen|included|in (the|this) capture)|no (trace|sign|messages|"
        r"traffic|signalling|signaling|record)|does(n't| not) (appear|show|contain|include)|"
        r"isn't in|absent|never (appears|shows))",
    ),
    reply_must_not=(
        r"(not provisioned|user unknown)",
        r"(attached|connected) (successfully|normally)",
    ),
    reference_reply=(
        "We can't tell yet: this SIM does not appear anywhere in the capture. The capture only "
        "shows three other SIMs attaching normally, so it was taken at another time or on "
        "another part of the network. Please send the exact time of a failed attempt and we "
        "will capture on the right interface."
    ),
    notes="Every procedure in the capture works, so 'no fault' is tempting, but the ticket's "
    "IMSI never appears. Nothing can be cited for the cause; the honest answer is that the "
    "capture cannot show it.",
)


def _t10() -> list[Frame]:
    s6a = _S6a()
    return [
        *s6a.attach(T0, IMSI(22)),
        *s6a.exchange(T0 + 3, AIR, IMSI(21), tags=(None, "aia_ok")),
        *s6a.exchange(T0 + 3.5, ULR, IMSI(21), experimental=5004, tags=("ulr", "ula_5004")),
        *s6a.exchange(T0 + 20, AIR, IMSI(21)),
        *s6a.exchange(T0 + 20.5, ULR, IMSI(21), experimental=5004),
    ]


T10 = Ticket(
    id="t10-no-service-abroad",
    ticket=(
        f"Our device {IMSI(21)} works at home, but abroad it shows 'no service'. It fails "
        "right at authentication, so we think the keys on the SIM are bad. Should we "
        "replace it?"
    ),
    subscriber=IMSI(21),
    root_cause="roaming_not_allowed",
    frames=_t10,
    key_tags=("ula_5004",),
    checks=(
        Check("ulr", f'diameter.User-Name == "{IMSI(21)}"'),
        Check("ula_5004", "diameter.Experimental-Result-Code == 5004"),
        Check("aia_ok", "diameter.Result-Code == 2001"),
    ),
    reply_must=(r"roaming",),
    reply_must_not=(
        r"(keys?|authentication|credentials) (is|are|was|were) (wrong|bad|failing|broken)",
        r"(replace|swap) (the )?sim",
    ),
    reference_reply=(
        "The SIM and its keys are fine: authentication succeeds. The network then refuses the "
        "location update because roaming is not allowed for this SIM in that country "
        "(roaming not allowed). We need to enable roaming on the subscription or for that "
        "network; no replacement is needed."
    ),
    notes="The customer blames authentication, which the capture shows succeeding (AIA "
    "2001). The refusal is the Update Location Answer, 5004.",
)


TICKETS: tuple[Ticket, ...] = (T01, T02, T03, T04, T05, T06, T07, T08, T09, T10)


def by_id(ticket_id: str) -> Ticket:
    for t in TICKETS:
        if t.id == ticket_id:
            return t
    raise KeyError(ticket_id)
