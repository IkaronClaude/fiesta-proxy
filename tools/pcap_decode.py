"""
pcap_decode.py — Fiesta-aware pcap inspector with cipher decryption and
PDB-driven struct decoding.

Source of truth for opcodes and struct layouts:
  lib/FiestaLib-Reloaded/docs/extracted/merged/{all-enums.json,all-structs.json}

For each TCP conversation in the pcap:
  * Pairs C->S with S->C by 4-tuple.
  * Reads the S->C 0x0807 (NC_MISC_SEED_ACK) handshake to learn the seed.
  * Decrypts C->S with the seed (XOR table from _fiesta_proto).
  * For every frame, prints:
      - direction arrow + index + raw offset
      - opcode + canonical name (e.g. 0x0C0C NC_USER_WORLDSELECT_ACK)
      - PDB-derived struct decode (per-field name/offset/type), Name<N>
        strings rendered as ASCII, scalars as decimal+hex.
      - xxd-style hex + ASCII dump of the raw payload.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import struct
import sys

import dpkt

# ⚠️ A REDIRECTED stdout on Windows defaults to the ANSI codepage (cp1252), and the hex dump prints raw
# packet bytes as latin-1 text -- so the first frame containing a byte cp1252 cannot map (0x81, 0x8D,
# 0x8F, 0x90, 0x9D, or 0x95) kills the process with UnicodeEncodeError, mid-dump.
#
# That is not cosmetic. The output looks like a complete decode that simply ends, so a grep over it
# reports a CONFIDENT ABSENCE: CombatPriest.pcapng was read here as having ZERO damage packets when it has
# 74 swings and 22 skill hits, because the dump died 40% of the way in. It only appears when the output is
# PIPED (an interactive console negotiates its own encoding) and only with the hex dump on -- i.e. exactly
# when a capture is being analysed rather than eyeballed.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, ValueError):
        pass

from _fiesta_proto import (
    XorCipher,
    is_handshake_body,
    opcode_of,
    parse_frames,
    payload_of,
)


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROTO_ROOT = os.path.normpath(os.path.join(
    SCRIPT_DIR, "..", "lib", "FiestaLib-Reloaded", "docs", "extracted", "merged"))


# Per-step movement spam (Act dept): the walk/run requests + their own/someone-else broadcasts
# that flood a busy zone and drown out everything interesting. --hide-movement suppresses ONLY
# these. Teleports / map-links / warps (NC_MAP_LINK*, NC_SKILL_WARP_CMD, mover ride on/off) are
# deliberately NOT here — those are meaningful transitions, not spam.
MOVEMENT_SPAM_OPS = {
    0x2003,  # NC_ACT_WALK_REQ          (C->S: my walk)
    0x2004,  # NC_ACT_SOMEONEWALK_CMD   (S->C: someone walks)
    0x2005,  # NC_ACT_RUN_REQ           (C->S: my run)
    0x2006,  # NC_ACT_SOMEONERUN_CMD    (S->C: someone runs)
    0x2017,  # NC_ACT_MOVEWALK_CMD      (my walk, broadcast form)
    0x2018,  # NC_ACT_SOMEONEMOVEWALK_CMD
    0x2019,  # NC_ACT_MOVERUN_CMD       (my run, broadcast form)
    0x201A,  # NC_ACT_SOMEONEMOVERUN_CMD
}


def print_usage_banner() -> None:
    """Always-on legend so the output is self-explanatory (printed before any frames)."""
    print("=" * 78)
    print("pcap_decode - Fiesta packet inspector (cipher-aware, PDB struct decode)")
    print("-" * 78)
    print("opcode = (department << 10) | command, shown as 0xNNNN + canonical NC_* name.")
    print("Directions:  S<- server->client (plaintext)   C-> client->server (XOR-decrypted)")
    print("  A garbage / '<unknown>' C-> stream means that conversation's 0x0807 handshake")
    print("  seed wasn't in the capture, so C->S can't be decrypted.")
    print("Flags: --port P(+)  --opcode 0xNNNN(+)  --no-hex  --no-struct  --hex-limit N")
    print("       --max-frames N (0=unlimited, default)  --no-interleave  --chat  --hide-movement")
    print("Interleave (timestamp-ordered, both directions) is ON by default — the only view that shows")
    print("  request->response pairing. Use --no-interleave for the old grouped-by-direction dump.")
    print("--hide-movement: drop per-step WALK/RUN spam (my + someone-else's moves);")
    print("  teleports / map-links / warps are KEPT (not movement spam).")
    print("=" * 78)


# ---- protocol metadata loading

def load_protocol():
    with open(os.path.join(PROTO_ROOT, "all-enums.json"), "r", encoding="utf-8") as f:
        enums = json.load(f)
    with open(os.path.join(PROTO_ROOT, "all-structs.json"), "r", encoding="utf-8") as f:
        sd = json.load(f)
    structs = sd["protocol_structs"]

    # opcode int -> NC_*_* name
    op_name: dict[int, str] = {}
    for dept_name, info in enums.items():
        dept_id = info["id"]
        for nc_name, code in info["opcodes"].items():
            op_int = (dept_id << 10) | code
            op_name[op_int] = nc_name

    # NC_* name -> struct name (PROTO_<NC_*>)
    name_to_struct: dict[str, dict] = {}
    for struct_name, struct_def in structs.items():
        if struct_name.startswith("PROTO_"):
            nc = struct_name[len("PROTO_"):]
            name_to_struct[nc] = struct_def

    return op_name, name_to_struct


# ---- pcap loading

def load_streams(path: str):
    bufs = collections.defaultdict(bytearray)
    seqs: dict[tuple, int] = {}
    segs: dict[tuple, list] = collections.defaultdict(list)  # key -> [(stream_offset, ts)]
    with open(path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        rdr = dpkt.pcapng.Reader(f) if magic == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(f)
        for ts, raw in rdr:
            try:
                eth = dpkt.ethernet.Ethernet(raw)
                ip = eth.data
            except Exception:
                continue
            if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
            data = bytes(tcp.data)
            if not data:
                continue
            key = (bytes(ip.src), tcp.sport, bytes(ip.dst), tcp.dport)
            if key not in seqs:
                seqs[key] = tcp.seq
            off = (tcp.seq - seqs[key]) & 0xFFFFFFFF
            buf = bufs[key]
            end = off + len(data)
            if end > len(buf):
                buf.extend(b"\x00" * (end - len(buf)))
            buf[off:end] = data
            segs[key].append((off, ts))
    streams = {k: bytes(v) for k, v in bufs.items()}
    seg_index = {k: sorted(v) for k, v in segs.items()}  # offset-sorted for lookup
    return streams, seg_index


def offset_ts(seg_list, off: int) -> float:
    """Timestamp of the TCP segment that delivered the byte at stream offset `off`
    (the largest segment start <= off). Used to order frames across both directions."""
    if not seg_list:
        return 0.0
    lo, hi, best = 0, len(seg_list) - 1, seg_list[0][1]
    while lo <= hi:
        mid = (lo + hi) // 2
        if seg_list[mid][0] <= off:
            best = seg_list[mid][1]; lo = mid + 1
        else:
            hi = mid - 1
    return best


def pair_conversations(streams: dict):
    seen = set()
    convos = []
    for key in streams:
        if key in seen:
            continue
        reverse = (key[2], key[3], key[0], key[1])
        seen.add(key)
        seen.add(reverse)
        if key[3] < key[1]:
            s2c_key = reverse if reverse in streams else None
            c2s_key = key
        else:
            s2c_key = key
            c2s_key = reverse if reverse in streams else None
        s2c_bytes = streams.get(s2c_key, b"") if s2c_key else b""
        c2s_bytes = streams.get(c2s_key, b"") if c2s_key else b""
        server_port = s2c_key[1] if s2c_key else (c2s_key[3] if c2s_key else 0)
        convos.append((s2c_key, s2c_bytes, c2s_key, c2s_bytes, server_port))
    return convos


def first_handshake_seed(s2c: bytes) -> int | None:
    for _off, _plen, body in parse_frames(s2c):
        ok, seed = is_handshake_body(body)
        if ok:
            return seed
    return None


# ---- struct decoding

SCALAR_FMT = {
    "char":               ("b", 1),
    "unsigned char":      ("B", 1),
    "signed char":        ("b", 1),
    "short":              ("h", 2),
    "unsigned short":     ("H", 2),
    "int":                ("i", 4),
    "unsigned int":       ("I", 4),
    "long":               ("i", 4),
    "unsigned long":      ("I", 4),
    "__int64":            ("q", 8),
    "unsigned __int64":   ("Q", 8),
    "float":              ("f", 4),
    "double":             ("d", 8),
    "bool":               ("?", 1),
}


def decode_field(payload: bytes, fld: dict, end: int) -> str:
    """Return a short human-readable rendering of one field's value."""
    off = fld["offset"]
    size = fld["size"]
    ty = fld["type"]
    if off >= end:
        return "<beyond payload>"
    avail = min(size, end - off)
    raw = payload[off:off + avail]

    # NameN / charN strings
    if ty.startswith("Name") or ty.startswith("char[") or ty == "char":
        # ASCII string, NUL-trimmed
        nul = raw.find(b"\x00")
        s = raw[:nul if nul >= 0 else avail]
        try:
            txt = s.decode("ascii")
        except UnicodeDecodeError:
            txt = s.decode("latin-1", errors="replace")
        return f"'{txt}'" + (f" (+{avail - len(s) - (1 if nul >= 0 else 0)} pad)" if avail > len(s) + 1 else "")

    # Fixed-size arrays "unsigned short[32]"
    if "[" in ty and ty.endswith("]"):
        base = ty[:ty.index("[")].strip()
        nstr = ty[ty.index("[") + 1:-1]
        if base in SCALAR_FMT:
            fmt, sz = SCALAR_FMT[base]
            n = avail // sz
            vals = struct.unpack("<" + fmt * n, raw[:n * sz]) if n else ()
            preview = vals[:8]
            tail = "..." if len(vals) > 8 else ""
            return f"{base}[{n}]: {list(preview)}{tail}"
        # struct array — just say count + size
        return f"{ty} ({avail}b)"

    # Plain scalar
    if ty in SCALAR_FMT:
        fmt, sz = SCALAR_FMT[ty]
        if avail >= sz:
            val = struct.unpack_from("<" + fmt, raw)[0]
            if isinstance(val, int):
                return f"{val} (0x{val & 0xFFFFFFFFFFFFFFFF:X})"
            return f"{val}"
        return "<truncated>"

    # Nested PROTO_* struct or unknown — show hex preview
    return f"{ty}: " + " ".join(f"{b:02x}" for b in raw[:min(avail, 16)]) + ("…" if avail > 16 else "")


def decode_struct(payload: bytes, struct_def: dict, indent: str = "    ") -> list[str]:
    out = []
    fields = struct_def.get("fields", [])
    end = len(payload)
    out.append(f"{indent}struct {struct_def['Name']}  sizeof={struct_def['SizeOf']}  payload={end}b")
    for fld in fields:
        rendered = decode_field(payload, fld, end)
        out.append(f"{indent}  @{fld['offset']:4d}  {fld['type']:24}  "
                   f"{fld['name']:24}  {rendered}")
    return out


# ---- rendering

def hex_ascii_rows(data: bytes, width: int = 16, indent: str = "      ") -> list[str]:
    rows = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        rows.append(f"{indent}{off:04x}  {hex_part}  |{ascii_part}|")
    return rows


def ip_to_str(b: bytes) -> str:
    if len(b) == 4:
        return ".".join(str(x) for x in b)
    if len(b) == 16:
        return ".".join(str(x) for x in b[:4])
    return b.hex()


def dump_frames(label: str, frames, op_name, name_to_struct,
                indent: str, show_hex: bool, hex_limit: int, show_struct: bool):
    for idx, (offset, prefix_len, body) in enumerate(frames):
        op = opcode_of(body)
        pl = payload_of(body)
        name = op_name.get(op, "<unknown>")
        print(f"{indent}{label} [{idx:3d}] @{offset:5d}  prefix={prefix_len}b  "
              f"[0x{op:04X}] {name}  payload={len(pl)}b")
        if show_struct:
            struct_def = name_to_struct.get(name)
            if struct_def:
                for line in decode_struct(pl, struct_def, indent + "  "):
                    print(line)
        if show_hex and pl:
            for line in hex_ascii_rows(pl[:hex_limit], indent=indent + "    "):
                print(line)
            if len(pl) > hex_limit:
                print(f"{indent}    ... +{len(pl) - hex_limit} bytes")


def extract_chat(body) -> str:
    """The longest printable-ASCII run in a chat frame's payload, as a clean line.
    Robust to the leading link-count/length bytes (and direction differences)."""
    pl = payload_of(body)
    best: list[str] = []
    cur: list[str] = []
    for b in pl:
        if 0x20 <= b < 0x7F:
            cur.append(chr(b))
        else:
            if len(cur) > len(best):
                best = cur
            cur = []
    if len(cur) > len(best):
        best = cur
    return "".join(best).strip()


def dump_one(label, off, body, op_name, name_to_struct, indent, show_hex, hex_limit, show_struct,
             ts=None):
    op = opcode_of(body)
    pl = payload_of(body)
    name = op_name.get(op, "<unknown>")
    # The byte offset orders frames WITHIN one direction and nothing more -- it is not a clock, and
    # anything with a duration (an abstate's restKeeptime, a cast time, a swing cadence) cannot be checked
    # against frame order. The capture has had a real timestamp per frame all along; --timestamps prints it.
    stamp = f" t={ts:.6f}" if ts is not None else ""
    print(f"{indent}{label} @{off:5d}{stamp}  [0x{op:04X}] {name}  payload={len(pl)}b")
    if show_struct:
        sd = name_to_struct.get(name)
        if sd:
            for line in decode_struct(pl, sd, indent + "  "):
                print(line)
    if show_hex and pl:
        for line in hex_ascii_rows(pl[:hex_limit], indent=indent + "    "):
            print(line)
        if len(pl) > hex_limit:
            print(f"{indent}    ... +{len(pl) - hex_limit} bytes")


# ---- main

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("pcap")
    p.add_argument("--port", type=int, action="append",
                   help="filter to conversations with this server port (repeatable)")
    p.add_argument("--no-hex", action="store_true")
    p.add_argument("--no-struct", action="store_true")
    p.add_argument("--hex-limit", type=int, default=128)
    p.add_argument("--max-frames", type=int, default=0,
                   help="cap frames per direction per conversation (0 = unlimited, the default)")
    p.add_argument("--opcode", action="append", type=lambda s: int(s, 0),
                   help="filter to one or more opcodes (repeatable)")
    # Interleaved (timestamp-ordered, both directions) is the DEFAULT — it's the only view that shows
    # request->response pairing, which is how you actually read a capture (see CLAUDE.md GOLDEN RULE).
    # Pass --no-interleave to fall back to the old grouped-by-direction dump.
    p.add_argument("--no-interleave", dest="interleave", action="store_false", default=True,
                   help="disable the default interleave; group frames by direction instead")
    p.add_argument("--chat", action="store_true",
                   help="print only chat messages (annotations), decoded as their own line, interleaved")
    p.add_argument("--timestamps", action="store_true",
                   help="print each frame's capture timestamp, in seconds from the first frame of the "
                        "conversation. Needed for anything with a DURATION -- abstate restKeeptime, cast "
                        "times, swing cadence -- because the @offset is not a clock.")
    p.add_argument("--hide-movement", action="store_true",
                   help="suppress per-step movement spam (walk/run, own + others); keeps teleports/map-links/warps")
    args = p.parse_args()

    print_usage_banner()
    op_name, name_to_struct = load_protocol()
    print(f"[meta] {len(op_name)} opcodes, {len(name_to_struct)} structs loaded"
          + ("  | --hide-movement ON" if args.hide_movement else ""))

    streams, segs = load_streams(args.pcap)
    convos = pair_conversations(streams)
    if args.port:
        convos = [c for c in convos if c[4] in args.port]

    for s2c_key, s2c, c2s_key, c2s, server_port in convos:
        if not s2c and not c2s:
            continue
        print()
        if s2c_key:
            print(f"==== server {ip_to_str(s2c_key[0])}:{s2c_key[1]} "
                  f"<-> client {ip_to_str(s2c_key[2])}:{s2c_key[3]} ====")
        else:
            print(f"==== server :{server_port} (s2c missing) ====")
        print(f"  S->C bytes={len(s2c)}  C->S bytes={len(c2s)}")

        seed = first_handshake_seed(s2c) if s2c else None
        if seed is not None:
            print(f"  seed (from S->C 0x0807 NC_MISC_SEED_ACK): 0x{seed:04X} ({seed})")

        s2c_seg = segs.get(s2c_key, []) if s2c_key else []
        c2s_seg = segs.get(c2s_key, []) if c2s_key else []

        # Collect frames tagged with the timestamp of the segment that delivered them, so
        # both directions can be merged into one chronological stream. C->S bodies are XOR'd.
        hidden_moves = [0]  # mutable counter shared across collect() calls (movement spam dropped)

        def collect(buf, seg, decrypt):
            out = []
            cipher = XorCipher(seed) if (decrypt and seed is not None) else None
            for off, plen, body in parse_frames(buf):
                b = cipher.transform(body) if cipher else body
                op = opcode_of(b)
                if args.hide_movement and op in MOVEMENT_SPAM_OPS:
                    hidden_moves[0] += 1
                    continue
                if args.opcode and op not in args.opcode:
                    continue
                out.append((offset_ts(seg, off), off, plen, b))
                if args.max_frames and len(out) >= args.max_frames:
                    break
            return out

        s2c_frames = collect(s2c, s2c_seg, False) if s2c else []
        c2s_frames = collect(c2s, c2s_seg, True) if c2s else []
        if args.hide_movement and hidden_moves[0]:
            print(f"  [hidden {hidden_moves[0]} movement frames]")

        # --chat: only chat messages (annotations), decoded as their own line, interleaved.
        if args.chat:
            rows = []
            for ts, off, _pl, b in s2c_frames:
                if "CHAT" in op_name.get(opcode_of(b), ""):
                    rows.append((ts, off, "S<-", extract_chat(b)))
            for ts, off, _pl, b in c2s_frames:
                if "CHAT" in op_name.get(opcode_of(b), ""):
                    rows.append((ts, off, "C->", extract_chat(b)))
            for ts, off, d, txt in sorted(rows):
                if txt:
                    print(f"  {d} chat: {txt}")
            continue

        # --interleave: both directions in one timestamp-ordered stream.
        if args.interleave:
            merged = [(ts, "S<-", off, b) for ts, off, _pl, b in s2c_frames] + \
                     [(ts, "C->", off, b) for ts, off, _pl, b in c2s_frames]
            merged.sort(key=lambda x: (x[0], x[2]))
            # Relative to this CONVERSATION's first frame, not the capture's. A relog opens a new
            # conversation and the two decode independently, so a capture-wide origin would put two
            # unrelated sessions on one axis.
            t0 = merged[0][0] if merged else 0.0
            print(f"  --- interleaved ({len(merged)}) ---")
            for ts, d, off, b in merged:
                dump_one(d, off, b, op_name, name_to_struct, indent="    ",
                         show_hex=not args.no_hex, hex_limit=args.hex_limit,
                         show_struct=not args.no_struct,
                         ts=(ts - t0) if args.timestamps else None)
            continue

        # default: S->C block then C->S block (as before)
        if s2c_frames:
            print(f"  --- S->C ({len(s2c_frames)}) ---")
            dump_frames("S<-", [(off, plen, b) for _ts, off, plen, b in s2c_frames], op_name, name_to_struct,
                        indent="    ", show_hex=not args.no_hex,
                        hex_limit=args.hex_limit, show_struct=not args.no_struct)
        if c2s_frames:
            print(f"  --- C->S decrypted ({len(c2s_frames)}) ---")
            dump_frames("C->", [(off, plen, b) for _ts, off, plen, b in c2s_frames], op_name, name_to_struct,
                        indent="    ", show_hex=not args.no_hex,
                        hex_limit=args.hex_limit, show_struct=not args.no_struct)

    return 0


if __name__ == "__main__":
    sys.exit(main())
