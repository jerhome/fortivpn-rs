#!/usr/bin/env python3
"""Génère le corpus seed des cibles de fuzzing depuis docs/vectors/*.hex.

Usage : python3 -I fuzz/gen_seeds.py   (écrit fuzz/seeds/<cible>/*, déterministe)
Format des .hex : docs/vectors/README.md.
"""
import pathlib
import shutil
import struct

ROOT = pathlib.Path(__file__).resolve().parent.parent
VEC = ROOT / "docs" / "vectors"
OUT = ROOT / "fuzz" / "seeds"
FILES = ["framing.hex", "lcp.hex", "ipcp.hex", "ip.hex"]


def load():
    vecs = []
    for name in FILES:
        cur = None
        for line in (VEC / name).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("@frame"):
                parts = line.split()
                kv = dict(p.split("=", 1) for p in parts[2:])
                cur = {"name": parts[1], "dir": kv.get("dir", ""), "len": int(kv["len"]), "bytes": bytearray()}
                vecs.append(cur)
                continue
            cur["bytes"].extend(int(t, 16) for t in line.split())
    for v in vecs:
        assert len(v["bytes"]) == v["len"], v["name"]
    return vecs


def is_wire(v):
    b = v["bytes"]
    return (not v["name"].startswith(("err_", "stream_"))) and len(b) >= 7 and b[2:4] == b"\x50\x50"


def write(target, name, data):
    d = OUT / target
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(bytes(data))


def frame_op(ppp):
    assert len(ppp) <= 255
    return bytes([0, len(ppp)]) + bytes(ppp)


def main():
    vecs = load()
    by = {v["name"]: v for v in vecs}
    if OUT.exists():
        shutil.rmtree(OUT)

    # frame_decoder : seed de découpage (4 o) + flux.
    for v in vecs:
        for i, seed in enumerate((b"\0\0\0\0", b"\x01\x02\x03\x04")):
            write("frame_decoder", f"{v['name']}_{i}", seed + v["bytes"])
    for d in ("g2c", "c2g"):
        stream = b"".join(bytes(v["bytes"]) for v in vecs if is_wire(v) and v["dir"] == d)
        write("frame_decoder", f"all_{d}", b"\x07\x00\x00\x00" + stream)

    # ppp_packet : max_len (2 o, MRU 1354) + trame PPP.
    for v in vecs:
        if is_wire(v):
            write("ppp_packet", v["name"], struct.pack(">H", 1354) + v["bytes"][6:])
        elif v["name"].endswith("_raw_ip"):
            write("ppp_packet", v["name"], struct.pack(">H", 1354) + b"\x00\x21" + v["bytes"])
    write("ppp_packet", "ff03_lcp", struct.pack(">H", 40) + b"\xff\x03" + by["lcp_confreq_gateway"]["bytes"][6:])

    # ppp_options : données des Configure-* (après proto + en-tête de contrôle).
    for v in vecs:
        b = v["bytes"]
        if is_wire(v) and b[6:8] in (b"\xc0\x21", b"\x80\x21") and 1 <= b[8] <= 4:
            write("ppp_options", v["name"], b[12:])

    # ppp_session : cfg(1 o = 0) + ops (voir fuzz_targets/ppp_session.rs).
    OPEN, JUMP = bytes([3]), bytes([2])
    g = lambda n: frame_op(by[n]["bytes"][6:])
    handshake = (
        b"\0" + OPEN
        + g("lcp_confreq_gateway") + g("lcp_confack_gateway")
        + g("ipcp_confreq_gateway") + g("ipcp_confnak_gateway")
        + bytes([5, 1])  # Ack de notre 2e requête IPCP
        + g("ipv4_icmp_echo_reply") + g("lcp_echo_request_gateway")
        + g("ipv6cp_confreq_gateway")
        + JUMP + JUMP + g("lcp_echo_reply_gateway")
        + g("lcp_terminate_request_gateway")
    )
    write("ppp_session", "handshake", handshake)
    write("ppp_session", "handshake_close", handshake[: -len(g("lcp_terminate_request_gateway"))]
          + bytes([4]) + g("lcp_terminate_ack_gateway"))
    write("ppp_session", "retransmit_until_fail", b"\0" + OPEN + JUMP * 12)
    write("ppp_session", "dead_peer",
          b"\0" + OPEN + g("lcp_confreq_gateway") + g("lcp_confack_gateway") + JUMP * 8)
    write("ppp_session", "lcp_reject", b"\0" + OPEN + g("lcp_confrej_gateway") + bytes([5, 0]))
    write("ppp_session", "ipcp_vj_reject", b"\0" + OPEN + g("lcp_confreq_gateway")
          + g("lcp_confack_gateway") + g("ipcp_confrej_gateway_vj") + g("ipcp_confreq_gateway_empty"))
    all_g2c = b"".join(g(v["name"]) for v in vecs if is_wire(v) and v["dir"] == "g2c")
    write("ppp_session", "all_g2c", b"\0" + OPEN + all_g2c)


if __name__ == "__main__":
    main()
