"""Synthetic packet builders, copied from capsight's tests/pcapgen.py (same author, MIT).

Every capture is synthetic: test-network IMSIs (001/01), RFC 5737 addresses, example.org.
"""

from __future__ import annotations

import struct
from pathlib import Path

TEST_IMSI = "001010000000001"
HOST_A = bytes([192, 0, 2, 10])  # e.g. MME
HOST_B = bytes([192, 0, 2, 20])  # e.g. HSS / SGW

# ---- link / network / transport --------------------------------------------------------


def _ipv4(src: bytes, dst: bytes, proto: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src, dst)
    return header + payload


def _eth(payload: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + payload


def udp_frame(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return _eth(_ipv4(src, dst, 17, udp))


class TcpFlow:
    """Minimal TCP stream (no handshake) so tshark dissects payloads by port."""

    def __init__(self, a: bytes, b: bytes, aport: int, bport: int) -> None:
        self.a, self.b, self.aport, self.bport = a, b, aport, bport
        self.seq = {True: 1000, False: 5000}

    def frame(self, from_a: bool, payload: bytes) -> bytes:
        src, dst = (self.a, self.b) if from_a else (self.b, self.a)
        sport, dport = (self.aport, self.bport) if from_a else (self.bport, self.aport)
        seq, ack = self.seq[from_a], self.seq[not from_a]
        tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, 0x18, 65535, 0, 0)
        self.seq[from_a] += len(payload)
        return _eth(_ipv4(src, dst, 6, tcp + payload))


def write_pcap(path: Path, frames: list[tuple[float, bytes]]) -> Path:
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)
    return path


# ---- Diameter ---------------------------------------------------------------------------

VENDOR_3GPP = 10415
S6A_APP = 16777251


def avp(code: int, data: bytes, vendor: int | None = None, mandatory: bool = True) -> bytes:
    flags = (0x40 if mandatory else 0) | (0x80 if vendor else 0)
    header_len = 12 if vendor else 8
    length = header_len + len(data)
    out = struct.pack("!IB", code, flags) + length.to_bytes(3, "big")
    if vendor:
        out += struct.pack("!I", vendor)
    out += data
    return out + b"\x00" * (-len(out) % 4)


def avp_u32(code: int, value: int, vendor: int | None = None) -> bytes:
    return avp(code, struct.pack("!I", value), vendor)


def avp_str(code: int, value: str, vendor: int | None = None) -> bytes:
    return avp(code, value.encode(), vendor)


def diameter(
    cmd: int, request: bool, hbh: int, e2e: int, avps: list[bytes], app: int = S6A_APP
) -> bytes:
    body = b"".join(avps)
    flags = 0xC0 if request else 0x40
    length = 20 + len(body)
    return (
        bytes([1])
        + length.to_bytes(3, "big")
        + bytes([flags])
        + cmd.to_bytes(3, "big")
        + struct.pack("!III", app, hbh, e2e)
        + body
    )


def _common(session: str, host: str) -> list[bytes]:
    return [
        avp_str(263, session),
        avp_str(264, host),
        avp_str(296, "example.org"),
    ]


def s6a_request(cmd: int, hbh: int, imsi: str = TEST_IMSI) -> bytes:
    return diameter(
        cmd,
        True,
        hbh,
        hbh + 1,
        [
            *_common(f"mme.example.org;{hbh}", "mme.example.org"),
            avp_str(283, "example.org"),
            avp_u32(277, 1),
            avp_str(1, imsi),
        ],
    )


def s6a_answer(
    cmd: int, hbh: int, result: int | None = 2001, experimental: int | None = None
) -> bytes:
    avps = _common(f"mme.example.org;{hbh}", "hss.example.org")
    if experimental is not None:
        avps.append(avp(297, avp_u32(266, VENDOR_3GPP) + avp_u32(298, experimental)))
    elif result is not None:
        avps.append(avp_u32(268, result))
    avps.append(avp_u32(277, 1))
    return diameter(cmd, False, hbh, hbh + 1, avps)


# ---- Gx / Gy (policy and charging) --------------------------------------------------------

GX_APP = 16777238
GY_APP = 4  # Diameter Credit-Control (Gy/Ro)
CC_INITIAL, CC_UPDATE, CC_TERMINATION = 1, 2, 3


def avp_group(code: int, children: list[bytes], vendor: int | None = None) -> bytes:
    return avp(code, b"".join(children), vendor)


def _experimental(code: int) -> bytes:
    return avp_group(297, [avp_u32(266, VENDOR_3GPP), avp_u32(298, code)])


def ccr(
    hbh: int,
    app: int = GY_APP,
    req_type: int = CC_INITIAL,
    imsi: str | None = TEST_IMSI,
    apn: str = "internet",
    extra: list[bytes] | None = None,
) -> bytes:
    avps = [
        *_common(f"pgw.example.org;{hbh}", "pgw.example.org"),
        avp_str(283, "example.org"),
        avp_u32(258, app),
        avp_u32(416, req_type),
        avp_u32(415, 0),
    ]
    if imsi:
        avps.append(avp_group(443, [avp_u32(450, 1), avp_str(444, imsi)]))
    avps.append(avp_str(30, apn))
    avps += extra or []
    return diameter(272, True, hbh, hbh + 1, avps, app=app)


def cca(
    hbh: int,
    app: int = GY_APP,
    req_type: int = CC_INITIAL,
    result: int | None = 2001,
    experimental: int | None = None,
    extra: list[bytes] | None = None,
) -> bytes:
    server = "ocs.example.org" if app == GY_APP else "pcrf.example.org"
    avps = [*_common(f"pgw.example.org;{hbh}", server), avp_u32(258, app)]
    if experimental is not None:
        avps.append(_experimental(experimental))
    elif result is not None:
        avps.append(avp_u32(268, result))
    avps += [avp_u32(416, req_type), avp_u32(415, 0)]
    avps += extra or []
    return diameter(272, False, hbh, hbh + 1, avps, app=app)


def mscc(rating_group: int, result: int | None = None, final_action: int | None = None) -> bytes:
    children = [avp_u32(432, rating_group)]
    if final_action is not None:
        children.append(avp_group(430, [avp_u32(449, final_action)]))
    if result is not None:
        children.append(avp_u32(268, result))
    return avp_group(456, children)


def charging_rule_report(rule: str, failure_code: int, status: int = 1) -> bytes:
    return avp_group(
        1018,
        [
            avp_str(1005, rule, VENDOR_3GPP),
            avp_u32(1019, status, VENDOR_3GPP),
            avp_u32(1031, failure_code, VENDOR_3GPP),
        ],
        VENDOR_3GPP,
    )


# ---- GTPv2-C ----------------------------------------------------------------------------


def _ie(ie_type: int, data: bytes, instance: int = 0) -> bytes:
    return struct.pack("!BHB", ie_type, len(data), instance & 0x0F) + data


def tbcd(digits: str) -> bytes:
    if len(digits) % 2:
        digits += "F"
    return bytes(int(digits[i + 1], 16) << 4 | int(digits[i], 16) for i in range(0, len(digits), 2))


def ie_imsi(imsi: str) -> bytes:
    return _ie(1, tbcd(imsi))


def ie_apn(apn: str) -> bytes:
    data = b"".join(bytes([len(label)]) + label.encode() for label in apn.split("."))
    return _ie(71, data)


def ie_cause(cause: int, remote: bool = False) -> bytes:
    # flags octet: bit 0 = CS (cause source: 1 = originated by a remote node)
    return _ie(2, bytes([cause, 0x01 if remote else 0x00]))


def ie_pdn_type(pdn_type: int) -> bytes:
    """1 = IPv4, 2 = IPv6, 3 = IPv4v6."""
    return _ie(99, bytes([pdn_type]))


def plmn(mcc: str, mnc: str) -> bytes:
    """3-octet PLMN identity (TS 24.008 10.5.1.13)."""
    mnc3 = mnc[2] if len(mnc) == 3 else "F"
    return bytes(
        [
            int(mcc[1]) << 4 | int(mcc[0]),
            int(mnc3, 16) << 4 | int(mcc[2]),
            int(mnc[1]) << 4 | int(mnc[0]),
        ]
    )


def ie_serving_network(mcc: str, mnc: str) -> bytes:
    return _ie(83, plmn(mcc, mnc))


def ie_rat_type(rat: int = 6) -> bytes:  # 6 = EUTRAN
    return _ie(82, bytes([rat]))


# F-TEID interface types (TS 29.274 8.22)
S8_SGW_GTPC = 6
S11_MME_GTPC = 10


def ie_fteid(interface: int, teid: int, ipv4: bytes = HOST_A, instance: int = 0) -> bytes:
    return _ie(87, bytes([0x80 | interface]) + struct.pack("!I", teid) + ipv4, instance)


def gtpv2(msg_type: int, seq: int, ies: list[bytes], teid: int = 0) -> bytes:
    body = b"".join(ies)
    length = 8 + len(body)  # TEID + seq + spare + IEs
    return (
        bytes([0x48, msg_type])
        + struct.pack("!H", length)
        + struct.pack("!I", teid)
        + seq.to_bytes(3, "big")
        + b"\x00"
        + body
    )


def gtpv2_frame(from_a: bool, payload: bytes) -> bytes:
    src, dst = (HOST_A, HOST_B) if from_a else (HOST_B, HOST_A)
    return udp_frame(src, dst, 2123, 2123, payload)


# ---- RADIUS -----------------------------------------------------------------------------

AAA_HOST = bytes([192, 0, 2, 30])


def radius(code: int, ident: int, attrs: list[tuple[int, bytes]] = ()) -> bytes:
    body = b"".join(bytes([t, 2 + len(v)]) + v for t, v in attrs)
    return struct.pack("!BBH", code, ident, 20 + len(body)) + b"\x00" * 16 + body


def radius_frame(from_gateway: bool, payload: bytes) -> bytes:
    src, dst = (HOST_B, AAA_HOST) if from_gateway else (AAA_HOST, HOST_B)
    sport, dport = (40100, 1812) if from_gateway else (1812, 40100)
    return udp_frame(src, dst, sport, dport, payload)


# ---- PFCP -------------------------------------------------------------------------------

UPF_HOST = bytes([192, 0, 2, 40])


def _pfcp_ie(ie_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ie_type, len(data)) + data


def pfcp(
    msg_type: int,
    seq: int,
    seid: int | None = None,
    cause: int | None = None,
    ies: list[bytes] | tuple[bytes, ...] = (),
) -> bytes:
    body = (_pfcp_ie(19, bytes([cause])) if cause is not None else b"") + b"".join(ies)
    if seid is None:
        header_rest = seq.to_bytes(3, "big") + b"\x00"
        flags = 0x20
    else:
        header_rest = struct.pack("!Q", seid) + seq.to_bytes(3, "big") + b"\x00"
        flags = 0x21
    length = len(header_rest) + len(body)
    return bytes([flags, msg_type]) + struct.pack("!H", length) + header_rest + body


def pfcp_fseid(seid: int, ipv4: bytes = HOST_B) -> bytes:
    """F-SEID: the SEID the UPF must use towards the SMF for this session."""
    return _pfcp_ie(57, bytes([0x02]) + struct.pack("!Q", seid) + ipv4)


def pfcp_create_pdr(ue_ip: bytes, instance: str = "internet") -> bytes:
    """Create PDR whose PDI carries the UE address and the network instance."""
    labels = b"".join(bytes([len(part)]) + part.encode() for part in instance.split("."))
    pdi = _pfcp_ie(20, b"\x00") + _pfcp_ie(22, labels) + _pfcp_ie(93, bytes([0x02]) + ue_ip)
    pdr = _pfcp_ie(56, struct.pack("!H", 1)) + _pfcp_ie(29, struct.pack("!I", 255))
    return _pfcp_ie(1, pdr + _pfcp_ie(2, pdi))


# Session Report Request IEs: usage report, and "PFCP session deleted by the UP function".
PFCP_DELETED_BY_UP = (_pfcp_ie(39, b"\x02"), _pfcp_ie(161, b"\x01"))


def pfcp_frame(from_smf: bool, payload: bytes) -> bytes:
    src, dst = (HOST_B, UPF_HOST) if from_smf else (UPF_HOST, HOST_B)
    return udp_frame(src, dst, 8805, 8805, payload)


# ---- GTP-U ------------------------------------------------------------------------------

UE_IP = bytes([10, 45, 0, 5])
DN_IP = bytes([203, 0, 113, 8])  # RFC 5737 TEST-NET-3, stands in for an internet host


def icmp_echo(src: bytes, dst: bytes, reply: bool = False) -> bytes:
    icmp = bytes([0 if reply else 8, 0]) + b"\x00\x00" + b"\x00\x01\x00\x01" + b"ping"
    return _ipv4(src, dst, 1, icmp)


def gtpu_frame(uplink: bool, inner: bytes, teid: int = 0xA002) -> bytes:
    gtp = bytes([0x30, 0xFF]) + struct.pack("!HI", len(inner), teid) + inner
    src, dst = (HOST_A, UPF_HOST) if uplink else (UPF_HOST, HOST_A)
    return udp_frame(src, dst, 2152, 2152, gtp)


def plain_ip_frame(inner: bytes) -> bytes:
    return _eth(inner)


# ---- SS7 over SIGTRAN: SCTP / M3UA / SCCP / TCAP / MAP ----------------------------------

STP_A = bytes([192, 0, 2, 50])  # e.g. visited network STP / VLR side
STP_B = bytes([192, 0, 2, 60])  # e.g. home network STP / HLR side
SSN_HLR, SSN_VLR, SSN_MSC, SSN_SGSN = 6, 7, 8, 149


def ber(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + value


def ber_int(tag: int, value: int) -> bytes:
    return ber(tag, value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True))


# MAP application contexts 0.4.0.0.1.0.<ac>.<version> (TS 29.002 17.3.3)
AC_NETWORK_LOC_UP, AC_INFO_RETRIEVAL, AC_GPRS_LOC_UP = 1, 14, 32
AC_SM_GATEWAY, AC_SM_MO_RELAY, AC_SM_MT_RELAY = 20, 21, 25
DIALOGUE_AS = bytes.fromhex("00118605010101")  # 0.0.17.773.1.1.1
MAP_DIALOGUE_AS = bytes.fromhex("04000001010101")  # 0.4.0.0.1.1.1.1


def _ac(ac: int, version: int) -> bytes:
    return ber(0x06, bytes([0x04, 0x00, 0x00, 0x01, 0x00, ac, version]))


def _dialogue(apdu: bytes) -> bytes:
    return ber(0x6B, ber(0x28, ber(0x06, DIALOGUE_AS) + ber(0xA0, apdu)))


def dialogue_request(ac: int, version: int = 3) -> bytes:
    return _dialogue(ber(0x60, ber(0x80, b"\x07\x80") + ber(0xA1, _ac(ac, version))))


def dialogue_response(ac: int, version: int = 3, result: int = 0, user_diag: int = 0) -> bytes:
    return _dialogue(
        ber(
            0x61,
            ber(0x80, b"\x07\x80")
            + ber(0xA1, _ac(ac, version))
            + ber(0xA2, ber_int(0x02, result))
            + ber(0xA3, ber(0xA1, ber_int(0x02, user_diag))),
        )
    )


def map_user_abort(choice: int = 0, value: int = 0) -> bytes:
    """ABRT with MAP-UserAbortInfo: choice 0 userSpecificReason, 2 resourceUnavailable,
    3 applicationProcedureCancellation (value = the enumerated reason)."""
    reason = ber(0x80 | choice, b"" if choice in (0, 1) else bytes([value]))
    user_info = ber(0xBE, ber(0x28, ber(0x06, MAP_DIALOGUE_AS) + ber(0xA0, ber(0xA4, reason))))
    return _dialogue(ber(0x64, ber(0x80, b"\x00") + user_info))


def invoke(invoke_id: int, opcode: int, param: bytes = b"") -> bytes:
    return ber(0xA1, ber_int(0x02, invoke_id) + ber_int(0x02, opcode) + param)


def result(invoke_id: int, opcode: int | None = None, param: bytes = b"") -> bytes:
    body = ber_int(0x02, invoke_id)
    if opcode is not None:
        body += ber(0x30, ber_int(0x02, opcode) + param)
    return ber(0xA2, body)


def error(invoke_id: int, code: int, param: bytes = b"") -> bytes:
    return ber(0xA3, ber_int(0x02, invoke_id) + ber_int(0x02, code) + param)


def reject(invoke_id: int, problem_tag: int, problem: int) -> bytes:
    """problem_tag: 0x80 general, 0x81 invoke, 0x82 returnResult, 0x83 returnError."""
    return ber(0xA4, ber_int(0x02, invoke_id) + ber_int(problem_tag, problem))


def _components(comps: list[bytes]) -> bytes:
    return ber(0x6C, b"".join(comps)) if comps else b""


def _tid(tag: int, tid: int) -> bytes:
    return ber(tag, tid.to_bytes(4, "big"))


def tc_begin(otid: int, comps: list[bytes], dialogue: bytes = b"") -> bytes:
    return ber(0x62, _tid(0x48, otid) + dialogue + _components(comps))


def tc_continue(otid: int, dtid: int, comps: list[bytes], dialogue: bytes = b"") -> bytes:
    return ber(0x65, _tid(0x48, otid) + _tid(0x49, dtid) + dialogue + _components(comps))


def tc_end(dtid: int, comps: list[bytes], dialogue: bytes = b"") -> bytes:
    return ber(0x64, _tid(0x49, dtid) + dialogue + _components(comps))


def tc_abort(dtid: int, p_abort: int | None = None, dialogue: bytes = b"") -> bytes:
    cause = ber_int(0x4A, p_abort) if p_abort is not None else b""
    return ber(0x67, _tid(0x49, dtid) + cause + dialogue)


def _sccp_address(ssn: int) -> bytes:
    return bytes([0x42, ssn])  # route on SSN, SSN present, ITU


def sccp_udt(called_ssn: int, calling_ssn: int, data: bytes) -> bytes:
    called, calling = _sccp_address(called_ssn), _sccp_address(calling_ssn)
    p1 = 3
    p2 = p1 - 1 + 1 + len(called)
    p3 = p2 - 1 + 1 + len(calling)
    return (
        bytes([0x09, 0x80, p1, p2, p3])
        + bytes([len(called)])
        + called
        + bytes([len(calling)])
        + calling
        + bytes([len(data)])
        + data
    )


def m3ua_data(sccp: bytes, opc: int = 100, dpc: int = 200) -> bytes:
    pd = struct.pack("!IIBBBB", opc, dpc, 3, 2, 0, 0) + sccp
    param = struct.pack("!HH", 0x0210, 4 + len(pd)) + pd + b"\x00" * (-len(pd) % 4)
    return struct.pack("!BBBBI", 1, 0, 1, 1, 8 + len(param)) + param


_next_tsn = {True: 1, False: 1}


def sctp_frame(from_a: bool, payloads: list[bytes]) -> bytes:
    """One SCTP packet; several payloads become several DATA chunks (bundling).

    TSNs increase per direction so tshark never mistakes a frame for a retransmission.
    """
    src, dst = (STP_A, STP_B) if from_a else (STP_B, STP_A)
    chunks = b""
    for payload in payloads:
        tsn = _next_tsn[from_a]
        _next_tsn[from_a] += 1
        data = struct.pack("!IHHI", tsn, 0, tsn & 0xFFFF, 3) + payload  # PPID 3 = M3UA
        chunk = struct.pack("!BBH", 0, 0x03, 4 + len(data)) + data
        chunks += chunk + b"\x00" * (-len(chunk) % 4)
    sport, dport = (2905, 2906) if from_a else (2906, 2905)  # distinct ends: TSN per side
    common = struct.pack("!HHII", sport, dport, 1, 0)
    return _eth(_ipv4(src, dst, 132, common + chunks))


def map_frame(from_a: bool, *tcap_messages: bytes, called: int = SSN_HLR, calling: int = SSN_VLR):
    """from_a: visited side (VLR/SGSN/SMSC) -> home side (HLR) when True."""
    if not from_a:
        called, calling = calling, called
    return sctp_frame(from_a, [m3ua_data(sccp_udt(called, calling, m)) for m in tcap_messages])


def map_imsi(imsi: str = TEST_IMSI, tag: int = 0x04) -> bytes:
    return ber(tag, tbcd(imsi))


# MAP operation codes (TS 29.002 17.5) and error codes (17.6) used by tests
OP_UL, OP_CL, OP_ISD, OP_UGL, OP_SRI_SM, OP_MO_FSM, OP_MT_FSM, OP_SAI = 2, 3, 7, 23, 45, 46, 44, 56


def sai_arg(imsi: str = TEST_IMSI) -> bytes:
    return ber(0x30, map_imsi(imsi, 0x80) + ber_int(0x02, 1))


def ul_arg(imsi: str = TEST_IMSI) -> bytes:
    addr = ber(0x04, b"\x91" + tbcd("1234567890"))
    return ber(0x30, map_imsi(imsi) + ber(0x81, b"\x91" + tbcd("1234567890")) + addr)
