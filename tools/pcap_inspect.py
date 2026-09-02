"""
fiesta pcap inspector.

Parses a pcap[ng] capture, reassembles per-flow TCP streams, looks for streams
that start with the Fiesta length-prefix framing, and dumps the framed packets
on each candidate Fiesta stream.

The framing is:
  * 1 byte L (1..254)            -> frame length = L
  * 1 byte 0x00 + 2 bytes LE     -> frame length = LE u16
followed by `frame_length` bytes whose first 2 LE bytes are the opcode.

Server -> client is plaintext (per Ikaron/fiesta-filter analysis), so frames
on that direction parse directly. Client -> server is XOR-encrypted after a
handshake [0x07, 0x08, posLo, posHi] notification flows S->C in plaintext;
the inspector logs that handshake but does not attempt to decrypt C->S.

Usage:
  python pcap_inspect.py <pcap-file> [--opcode 0xNNNN] [--port 9010]
"""
from __future__ import annotations

import argparse
import collections
import struct
import sys

import dpkt


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("pcap")
    p.add_argument("--opcode", help="filter to a single opcode (e.g. 0x0C0A)")
    p.add_argument("--port", type=int, help="filter to a single TCP port")
    p.add_argument("--max-frames", type=int, default=200)
    p.add_argument("--hex-limit", type=int, default=HEX_LIMIT_DEFAULT,
                   help=f"hex bytes per frame (0 = unlimited; default {HEX_LIMIT_DEFAULT}). "
                        f"Anything withheld is reported loudly, never dropped silently.")
    return p.parse_args()


def iter_pcap(path: str):
    """Yield (ts, ip_pkt) for IPv4 TCP packets only."""
    with open(path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            reader = dpkt.pcapng.Reader(f)
        else:
            reader = dpkt.pcap.Reader(f)
        for ts, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
            except Exception:
                continue
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            yield ts, ip, tcp


class Reassembler:
    """Per-direction TCP byte reassembly keyed by (src, sport, dst, dport).
    Assumes well-behaved capture (no major loss); jumps that move SEQ forward
    by more than 1MB are reset rather than buffered."""

    def __init__(self) -> None:
        self.buffers: dict[tuple, bytearray] = collections.defaultdict(bytearray)
        self.first_seq: dict[tuple, int] = {}

    def feed(self, ip: dpkt.ip.IP, tcp: dpkt.tcp.TCP) -> tuple[tuple, bytes]:
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        seq = tcp.seq
        data = bytes(tcp.data)
        if not data:
            return key, b""
        if key not in self.first_seq:
            self.first_seq[key] = seq
        # Stream-position from first observed seq, modulo 2^32.
        off = (seq - self.first_seq[key]) & 0xFFFFFFFF
        if off > 0x100000 + len(self.buffers[key]):
            # Massive jump => treat as new stream (e.g. SEQ wraparound or loss).
            self.first_seq[key] = seq
            self.buffers[key].clear()
            off = 0
        buf = self.buffers[key]
        end = off + len(data)
        if end > len(buf):
            buf.extend(b"\x00" * (end - len(buf)))
        buf[off:end] = data
        return key, data


def try_parse_frames(buf: bytes, max_frames: int) -> list[tuple[int, bytes]]:
    """Return [(opcode, payload), ...] parsed from a candidate Fiesta byte stream.
    Stops at any malformed length-prefix to keep noise quiet."""
    out: list[tuple[int, bytes]] = []
    i = 0
    n = len(buf)
    while i < n and len(out) < max_frames:
        first = buf[i]
        if first != 0x00:
            frame_len = first
            i += 1
        else:
            if i + 2 >= n:
                break
            frame_len = buf[i + 1] | (buf[i + 2] << 8)
            i += 3
        if frame_len < 2:
            break
        if i + frame_len > n:
            break  # incomplete tail
        opcode = buf[i] | (buf[i + 1] << 8)
        payload = bytes(buf[i + 2 : i + frame_len])
        out.append((opcode, payload))
        i += frame_len
    return out, i


def is_fiesta_like(buf: bytes) -> bool:
    """Cheap heuristic: try to parse 3+ frames without bailing."""
    if len(buf) < 8:
        return False
    frames, _ = try_parse_frames(buf, max_frames=3)
    return len(frames) >= 2


def ip_to_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)


# Same default, and the same reasoning, as `pcap_decode.HEX_LIMIT_DEFAULT`: a limit low enough to cut a
# real payload in half turns "I read the frame" into "I read the first part of the frame and did not
# notice". 0 means unlimited.
HEX_LIMIT_DEFAULT = 65536


def hex_dump(payload: bytes, limit: int) -> str:
    head = payload if limit <= 0 else payload[:limit]
    out = " ".join(f"{b:02x}" for b in head)
    if len(head) < len(payload):
        # Shouts, rather than trailing quietly after the bytes it withheld.
        out += (f"  !! ({len(payload) - len(head)} BYTES NOT DISPLAYED!) payload is {len(payload)}b, "
                f"--hex-limit is {limit} -- RAISE IT (0 = unlimited)")
    return out


def main() -> int:
    args = parse_args()
    opcode_filter = int(args.opcode, 0) if args.opcode else None

    re = Reassembler()
    for _ts, ip, tcp in iter_pcap(args.pcap):
        re.feed(ip, tcp)

    candidates = []
    for key, buf in re.buffers.items():
        if not buf:
            continue
        if args.port is not None:
            src_ip, sport, dst_ip, dport = key
            if args.port not in (sport, dport):
                continue
        if is_fiesta_like(bytes(buf)):
            candidates.append((key, bytes(buf)))

    if not candidates:
        print("No Fiesta-framed streams detected.", file=sys.stderr)
        return 1

    for key, buf in candidates:
        src_ip, sport, dst_ip, dport = key
        frames, consumed = try_parse_frames(buf, max_frames=args.max_frames)
        if not frames:
            continue
        if opcode_filter is not None:
            keep = [f for f in frames if f[0] == opcode_filter]
            if not keep:
                continue
            frames = keep
        print(
            f"\n=== {ip_to_str(src_ip)}:{sport} -> {ip_to_str(dst_ip)}:{dport}  "
            f"({len(buf)} bytes, {len(frames)} frame(s) shown) ==="
        )
        for idx, (opcode, payload) in enumerate(frames):
            print(
                f"  [{idx:3d}] opcode=0x{opcode:04X} ({opcode}) "
                f"payload_len={len(payload)}  {hex_dump(payload, args.hex_limit)}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
