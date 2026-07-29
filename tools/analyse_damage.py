#!/usr/bin/env python
"""
analyse_damage.py — Wireshark (pcapng) SWING_DAMAGE analyser for reverse-engineering
the damage formula from operator-driven captures.

Built on the same machinery as pcap_decode.py (framing + C->S XOR decrypt + per-conversation
seed + stream separation). Adds:

  * GLOBAL PACKET IDs — every frame across ALL streams/directions is numbered in capture
    (timestamp) order, so you can reference a window like "packets 4000..4320".
  * CHAT ANNOTATION listing — print every chat line with its packet ID, so you can read off
    your own running commentary ("now I fight with X def") and grab the packet-ID range it brackets.
  * STREAM separation — each TCP conversation is a numbered stream. Running TWO clients at once
    (PVP) gives two streams; --stream picks one so the two views don't double-count.
  * ENTITY ROSTER — handle -> mob-id (from NC_BRIEFINFO_REGENMOB) / player name, so --mob-id
    resolves to the attacker handle(s) without hardcoding anything.
  * DAMAGE HISTOGRAM — DMG | Count table over NC_BAT_SWING_DAMAGE within a packet range,
    filtered by mob-id / attacker / defender / stream.

Needs the C->S XOR table for chat/annotation decode (S->C incl. SWING_DAMAGE is plaintext):
  XOR_TABLE_PATH=C:/Projects/ik-fiesta-bots/xor-table.hex

USAGE
  python analyse_damage.py <cap.pcapng> streams
  python analyse_damage.py <cap.pcapng> chat [--stream N]
  python analyse_damage.py <cap.pcapng> roster [--stream N]
  python analyse_damage.py <cap.pcapng> damage --mob-id 1234 --start-packet 4000 --end-packet 4320 [--stream N]
  python analyse_damage.py <cap.pcapng> damage --attacker 6935 --defender 828   # by raw handle (e.g. PVP)
"""
from __future__ import annotations

import argparse
import collections
import statistics
import sys

from _fiesta_proto import (
    parse_frames, opcode_of, payload_of, XorCipher, ip_to_str,
)
from pcap_decode import (
    load_protocol, load_streams, pair_conversations, first_handshake_seed,
    offset_ts, extract_chat,
)


def read_fields(struct_def, body, wanted):
    """Read named integer fields (size 1/2/4, little-endian) from a frame body's payload."""
    pl = payload_of(body)
    out = {}
    for fld in struct_def.get("fields", []):
        if fld["name"] not in wanted:
            continue
        o, sz = fld["offset"], fld["size"]
        if o + sz <= len(pl):
            out[fld["name"]] = int.from_bytes(pl[o:o + sz], "little")
    return out


def build_index(pcap, port_filter=None):
    """Return (op_name, name_to_struct, streams_meta, frames).

    frames: list of dicts {pid, ts, sid, dir, off, op, opname, body} in capture order,
    numbered 1..N by (timestamp, stream, offset). C->S bodies are decrypted; S->C plaintext.
    """
    op_name, name_to_struct = load_protocol()
    streams, segs = load_streams(pcap)
    convos = pair_conversations(streams)
    if port_filter:
        convos = [c for c in convos if c[4] in port_filter]

    frames = []
    streams_meta = []
    for sid, (s2c_key, s2c, c2s_key, c2s, server_port) in enumerate(convos):
        seed = first_handshake_seed(s2c) if s2c else None
        if s2c_key:
            client = f"{ip_to_str(s2c_key[2])}:{s2c_key[3]}"
        elif c2s_key:
            client = f"{ip_to_str(c2s_key[0])}:{c2s_key[1]}"
        else:
            client = "?"
        streams_meta.append(dict(sid=sid, client=client, server_port=server_port,
                                 seed=seed, s2c_bytes=len(s2c), c2s_bytes=len(c2s)))

        if s2c:
            seg = segs.get(s2c_key, [])
            for off, _plen, body in parse_frames(s2c):
                frames.append(dict(ts=offset_ts(seg, off), sid=sid, dir="S<-",
                                   off=off, op=opcode_of(body), body=body))
        if c2s:
            seg = segs.get(c2s_key, [])
            cipher = XorCipher(seed) if seed is not None else None
            for off, _plen, body in parse_frames(c2s):
                b = cipher.transform(body) if cipher else body   # stateful, in stream order
                frames.append(dict(ts=offset_ts(seg, off), sid=sid, dir="C->",
                                   off=off, op=opcode_of(b), body=b))

    frames.sort(key=lambda f: (f["ts"], f["sid"], f["off"]))
    for i, f in enumerate(frames):
        f["pid"] = i + 1
        f["opname"] = op_name.get(f["op"], "<unknown>")
    return op_name, name_to_struct, streams_meta, frames


def build_roster(frames, op_name, name_to_struct):
    """handle -> {'label','mobid','first_pid'} from NC_BRIEFINFO_REGENMOB (mobs) and any
    briefinfo struct exposing handle+mobid. Player briefinfos (name) added when present."""
    name_to_op = {v: k for k, v in op_name.items()}
    regen_op = name_to_op.get("NC_BRIEFINFO_REGENMOB_CMD")
    roster = {}
    for f in frames:
        if regen_op is not None and f["op"] == regen_op:
            sd = name_to_struct.get("NC_BRIEFINFO_REGENMOB_CMD")
            v = read_fields(sd, f["body"], {"handle", "mobid"})
            h, m = v.get("handle"), v.get("mobid")
            if h is not None and h not in roster:
                roster[h] = dict(label=f"mob{m}", mobid=m, first_pid=f["pid"])
    return roster


def cmd_streams(meta, frames):
    print(f"{'stream':<7} {'client':<24} {'srv_port':<9} {'seed':<8} {'frames':<8} pid_range")
    by_sid = collections.defaultdict(list)
    for f in frames:
        by_sid[f["sid"]].append(f["pid"])
    for m in meta:
        pids = by_sid.get(m["sid"], [])
        rng = f"{min(pids)}..{max(pids)}" if pids else "-"
        seed = f"0x{m['seed']:04X}" if m["seed"] is not None else "none"
        print(f"{m['sid']:<7} {m['client']:<24} {m['server_port']:<9} {seed:<8} {len(pids):<8} {rng}")
    print(f"\nTotal frames: {len(frames)}  (packet IDs are global, capture-time order)")


def cmd_chat(frames, op_name, stream=None):
    print(f"{'PID':>7}  {'strm':>4}  {'dir':<3}  chat")
    n = 0
    for f in frames:
        if stream is not None and f["sid"] != stream:
            continue
        if "CHAT" not in f["opname"]:
            continue
        txt = extract_chat(f["body"])
        if txt:
            print(f"{f['pid']:>7}  {f['sid']:>4}  {f['dir']:<3}  {txt}")
            n += 1
    print(f"\n{n} chat annotation(s). Use a PID as --start-packet/--end-packet for a damage window.")


def cmd_roster(frames, op_name, name_to_struct, stream=None):
    roster = build_roster(frames, op_name, name_to_struct)
    print(f"{'handle':>7}  {'mobid':>6}  {'first_seen_pid':>14}  label")
    for h, info in sorted(roster.items(), key=lambda kv: kv[1]["first_pid"]):
        print(f"{h:>7}  {str(info['mobid']):>6}  {info['first_pid']:>14}  {info['label']}")
    print(f"\n{len(roster)} entities seen (from NC_BRIEFINFO_REGENMOB). "
          f"Pass a mobid to `damage --mob-id`, or a handle to --attacker/--defender.")


def cmd_damage(frames, op_name, name_to_struct, args):
    name_to_op = {v: k for k, v in op_name.items()}
    swing_op = name_to_op.get("NC_BAT_SWING_DAMAGE_CMD")
    if swing_op is None:
        print("!! NC_BAT_SWING_DAMAGE_CMD opcode not found in protocol", file=sys.stderr)
        return 2
    sd = name_to_struct["NC_BAT_SWING_DAMAGE_CMD"]

    # resolve --mob-id to the set of attacker handles for that mob (from the roster)
    mob_handles = None
    if args.mob_id is not None:
        roster = build_roster(frames, op_name, name_to_struct)
        mob_handles = {h for h, i in roster.items() if i["mobid"] == args.mob_id}
        if not mob_handles:
            print(f"!! no handle in the capture maps to mob-id {args.mob_id} "
                  f"(check `roster`); is the mob's REGENMOB in this capture?", file=sys.stderr)
            return 3
        print(f"# mob-id {args.mob_id} -> attacker handle(s) {sorted(mob_handles)}")

    lo = args.start_packet if args.start_packet is not None else 0
    hi = args.end_packet if args.end_packet is not None else float("inf")

    hist = collections.Counter()
    samples = []
    pid_seen = []
    for f in frames:
        if f["op"] != swing_op:
            continue
        if not (lo <= f["pid"] <= hi):
            continue
        if args.stream is not None and f["sid"] != args.stream:
            continue
        v = read_fields(sd, f["body"], {"attacker", "defender", "damage"})
        atk, dfn, dmg = v.get("attacker"), v.get("defender"), v.get("damage")
        if mob_handles is not None and atk not in mob_handles:
            continue
        if args.attacker is not None and atk != args.attacker:
            continue
        if args.defender is not None and dfn != args.defender:
            continue
        hist[dmg] += 1
        samples.append(dmg)
        pid_seen.append(f["pid"])

    filt = []
    if args.mob_id is not None:
        filt.append(f"mob-id={args.mob_id}")
    if args.attacker is not None:
        filt.append(f"attacker={args.attacker}")
    if args.defender is not None:
        filt.append(f"defender={args.defender}")
    if args.stream is not None:
        filt.append(f"stream={args.stream}")
    filt.append(f"pid {lo}..{'end' if hi == float('inf') else int(hi)}")
    print(f"# SWING_DAMAGE filter: {', '.join(filt)}")

    if not samples:
        print("(no matching SWING_DAMAGE frames)")
        return 0

    print(f"\n{'DMG':>5} | Count")
    print("------+------")
    for dmg in sorted(hist):
        bar = "#" * min(hist[dmg], 60)
        print(f"{dmg:>5} | {hist[dmg]:<4} {bar}")
    print("------+------")
    print(f"n={len(samples)}  min={min(samples)}  max={max(samples)}  "
          f"mean={statistics.mean(samples):.2f}  median={statistics.median(samples)}  "
          f"stdev={statistics.pstdev(samples):.2f}")
    print(f"pid span of matches: {min(pid_seen)}..{max(pid_seen)}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Fiesta pcapng SWING_DAMAGE analyser")
    p.add_argument("pcap")
    p.add_argument("--port", type=int, action="append",
                   help="restrict to conversations on this server port (repeatable)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("streams", help="list TCP streams (one per client) + their packet-ID ranges")

    pc = sub.add_parser("chat", help="list chat annotations with their packet IDs")
    pc.add_argument("--stream", type=int)

    pr = sub.add_parser("roster", help="list handle -> mob-id/name entities")
    pr.add_argument("--stream", type=int)

    pd = sub.add_parser("damage", help="DMG|Count histogram of SWING_DAMAGE")
    pd.add_argument("--mob-id", type=int, help="attacker resolves to this mob-id (via REGENMOB roster)")
    pd.add_argument("--attacker", type=int, help="filter by raw attacker handle")
    pd.add_argument("--defender", type=int, help="filter by raw defender handle (e.g. the char taking dmg)")
    pd.add_argument("--stream", type=int, help="only this stream (avoid double-count in 2-client captures)")
    pd.add_argument("--start-packet", type=int)
    pd.add_argument("--end-packet", type=int)

    args = p.parse_args()

    op_name, name_to_struct, meta, frames = build_index(args.pcap, args.port)

    if args.cmd == "streams":
        cmd_streams(meta, frames)
    elif args.cmd == "chat":
        cmd_chat(frames, op_name, args.stream)
    elif args.cmd == "roster":
        cmd_roster(frames, op_name, name_to_struct, args.stream)
    elif args.cmd == "damage":
        return cmd_damage(frames, op_name, name_to_struct, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
