"""
Replay a single TCP stream from a Fiesta pcap against a live target (the proxy
in docker, or the bare server if you want to compare).

What it does:
  1. Picks one C->S stream from the capture by --capture-port (and optional
     --client-port for disambiguation).
  2. Reads the matching S->C stream and observes the cipher handshake
     [0x0807 + 2-byte seed]. This gives the seed the captured client used.
  3. Connects to --target, waits for the target's S->C handshake to learn
     the new seed the live server has chosen.
  4. For each captured C->S frame:
       - decrypt body with the capture's seed cipher
       - re-encrypt body with the live target's seed cipher
       - emit length prefix + re-encrypted body to the target socket
  5. Reads everything the target sends back (plaintext) and parses frames.
     Frames matching --watch-opcodes are pretty-printed with field
     decoding so 0x0C0C / 0x1003 rewrites are easy to spot.

Usage:
  python replay.py <pcap> --capture-port 9010 --target 127.0.0.1:9010
  python replay.py <pcap> --capture-port 9110 --target 127.0.0.1:9110
"""
from __future__ import annotations

import argparse
import collections
import socket
import struct
import sys
import time

import dpkt

from _fiesta_proto import (
    XorCipher,
    encode_frame,
    is_handshake_body,
    ip_to_str,
    opcode_of,
    parse_frames,
    payload_of,
)


WATCH_DEFAULT = "0x0807,0x0C0C,0x1003"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("pcap")
    p.add_argument("--capture-port", type=int, required=True, help="server port in the capture (9010, 9110, ...)")
    p.add_argument("--client-port", type=int, default=None, help="optional ephemeral client port to disambiguate")
    p.add_argument("--target", required=True, help="host:port to dial (the proxy)")
    p.add_argument("--watch-opcodes", default=WATCH_DEFAULT, help="comma-separated opcodes to decode/highlight")
    p.add_argument("--max-frames", type=int, default=200, help="max C->S frames to replay")
    p.add_argument("--read-timeout", type=float, default=3.0)
    p.add_argument("--inter-frame-delay", type=float, default=0.02)
    p.add_argument("--dry-run", action="store_true", help="don't open a socket; just print what would be sent")
    p.add_argument("--patch-version-md5", default=None,
                   help="hex MD5 (32 chars) to substitute into opcode 0x0C65 USER_CLIENT_VERSION_CHECK_REQ "
                        "payload bytes 0..31 before sending. Use when the target server expects a different "
                        "client version than the one the capture was made with.")
    p.add_argument("--login-user", default=None,
                   help="override sUserName (@0, char[260]) in the 0x0C5A NC_USER_US_LOGIN_REQ frame")
    p.add_argument("--login-pw-md5", default=None,
                   help="override sPassword (@260, char[36]) in 0x0C5A with this MD5 hex (32 chars)")
    return p.parse_args()


def load_streams(pcap_path: str):
    """Reassemble both directions, return dict[(src,sport,dst,dport)] = bytes."""
    bufs: dict[tuple, bytearray] = collections.defaultdict(bytearray)
    first_seq: dict[tuple, int] = {}
    with open(pcap_path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        reader = dpkt.pcapng.Reader(f) if magic == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(f)
        for _ts, raw in reader:
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
            seq = tcp.seq
            if key not in first_seq:
                first_seq[key] = seq
            off = (seq - first_seq[key]) & 0xFFFFFFFF
            buf = bufs[key]
            end = off + len(data)
            if end > len(buf):
                buf.extend(b"\x00" * (end - len(buf)))
            buf[off:end] = data
    return {k: bytes(v) for k, v in bufs.items()}


def pick_streams(streams: dict, capture_port: int, client_port: int | None):
    """Return ((c2s_bytes), (s2c_bytes), (c_ip, c_port), (s_ip, s_port))."""
    candidates = []
    for key, buf in streams.items():
        src_ip, sport, dst_ip, dport = key
        if dport == capture_port:
            # client (src) -> server (dst)
            c2s = buf
            s2c_key = (dst_ip, dport, src_ip, sport)
            s2c = streams.get(s2c_key, b"")
            if client_port is not None and sport != client_port:
                continue
            candidates.append((c2s, s2c, (src_ip, sport), (dst_ip, dport)))
    if not candidates:
        return None
    # Pick the longest C->S stream as the most-likely full session.
    candidates.sort(key=lambda t: len(t[0]), reverse=True)
    return candidates[0]


def extract_capture_seed(s2c: bytes) -> int | None:
    for _off, _plen, body in parse_frames(s2c):
        ok, seed = is_handshake_body(body)
        if ok:
            return seed
    return None


def decode_watch_frame(opcode: int, payload: bytes) -> str:
    """Decode known opcodes for human-readable output."""
    if opcode == 0x0807 and len(payload) == 2:
        seed = payload[0] | (payload[1] << 8)
        return f"HANDSHAKE seed=0x{seed:04X} ({seed})"
    if opcode == 0x0C0C and len(payload) >= 19:
        status = payload[0]
        ip_field = payload[1:17]
        nul = ip_field.find(b"\x00")
        ip = ip_field[:nul if nul >= 0 else 16].decode("ascii", errors="replace")
        port = payload[17] | (payload[18] << 8)
        return f"WORLDSELECT_ACK status={status} ip={ip!r} port={port}"
    if opcode == 0x1003 and len(payload) >= 18:
        ip_field = payload[0:16]
        nul = ip_field.find(b"\x00")
        ip = ip_field[:nul if nul >= 0 else 16].decode("ascii", errors="replace")
        port = payload[16] | (payload[17] << 8)
        return f"CHAR_LOGIN_ACK ip={ip!r} port={port}"
    return ""


def short_hex(b: bytes, limit: int = 32) -> str:
    head = b[:limit]
    s = " ".join(f"{x:02x}" for x in head)
    if len(b) > limit:
        s += f" ... (+{len(b) - limit})"
    return s


def main() -> int:
    args = parse_args()
    watch = {int(s, 0) for s in args.watch_opcodes.split(",") if s.strip()}

    target_host, target_port_s = args.target.rsplit(":", 1)
    target_port = int(target_port_s)

    print(f"[load] {args.pcap}")
    streams = load_streams(args.pcap)
    picked = pick_streams(streams, args.capture_port, args.client_port)
    if not picked:
        print(f"No stream found for capture port {args.capture_port}", file=sys.stderr)
        return 1
    c2s_buf, s2c_buf, client_ep, server_ep = picked
    print(f"[stream] client {ip_to_str(client_ep[0])}:{client_ep[1]} -> server {ip_to_str(server_ep[0])}:{server_ep[1]}")
    print(f"[stream] C->S bytes={len(c2s_buf)}  S->C bytes={len(s2c_buf)}")

    capture_seed = extract_capture_seed(s2c_buf)
    if capture_seed is None:
        print("No 0x0807 cipher handshake in capture S->C — refusing to replay (would send plaintext to encrypted server).", file=sys.stderr)
        return 1
    print(f"[cipher] capture seed = 0x{capture_seed:04X} ({capture_seed})")

    capture_cipher = XorCipher(capture_seed)
    decrypted_bodies: list[bytes] = []
    for _off, _plen, body in parse_frames(c2s_buf):
        decrypted_bodies.append(capture_cipher.transform(body))
        if len(decrypted_bodies) >= args.max_frames:
            break
    print(f"[cipher] decrypted {len(decrypted_bodies)} captured C->S frames")

    if args.patch_version_md5:
        new_hex = args.patch_version_md5.strip().lower()
        if len(new_hex) != 32:
            print(f"--patch-version-md5 must be exactly 32 hex chars, got {len(new_hex)}", file=sys.stderr)
            return 1
        patched = 0
        for i, body in enumerate(decrypted_bodies):
            if opcode_of(body) == 0x0C65 and len(body) >= 2 + 32:
                payload = bytearray(payload_of(body))
                # payload[0..31] is the version MD5 as ASCII hex chars
                payload[0:32] = new_hex.encode("ascii")
                decrypted_bodies[i] = bytes(body[:2]) + bytes(payload)
                patched += 1
        print(f"[patch] substituted version MD5 in {patched} 0x0C65 frame(s) -> {new_hex}")

    if args.login_user or args.login_pw_md5:
        patched = 0
        for i, body in enumerate(decrypted_bodies):
            if opcode_of(body) == 0x0C5A and len(body) >= 2 + 296:
                payload = bytearray(payload_of(body))
                if args.login_user:
                    payload[0:260] = b"\x00" * 260
                    payload[0:len(args.login_user)] = args.login_user.encode("ascii")
                if args.login_pw_md5:
                    pw = args.login_pw_md5.strip().encode("ascii")
                    payload[260:296] = b"\x00" * 36
                    payload[260:260 + len(pw)] = pw
                decrypted_bodies[i] = bytes(body[:2]) + bytes(payload)
                patched += 1
        print(f"[patch] rewrote credentials in {patched} 0x0C5A frame(s) -> user={args.login_user} pw={args.login_pw_md5}")

    if args.dry_run:
        for i, body in enumerate(decrypted_bodies):
            op = opcode_of(body)
            print(f"  [{i:3d}] opcode=0x{op:04X} payload_len={len(body) - 2}  {short_hex(payload_of(body))}")
        return 0

    sock = socket.create_connection((target_host, target_port), timeout=args.read_timeout)
    sock.settimeout(args.read_timeout)
    print(f"[net] connected to {target_host}:{target_port}")

    rx_buf = bytearray()
    target_cipher: XorCipher | None = None

    def drain_once() -> bytes:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            return b""
        return chunk

    # Phase 1: wait for target's handshake to learn its seed.
    deadline = time.monotonic() + args.read_timeout
    while target_cipher is None and time.monotonic() < deadline:
        chunk = drain_once()
        if not chunk:
            continue
        rx_buf.extend(chunk)
        parsed_count = 0
        for _off, _plen, body in parse_frames(bytes(rx_buf)):
            parsed_count += 1
            op = opcode_of(body)
            pl = payload_of(body)
            note = decode_watch_frame(op, pl) if op in watch else ""
            tag = f"  << [{op:04X}]"
            print(f"{tag} payload_len={len(pl)}  {short_hex(pl)}" + (f"   {note}" if note else ""))
            ok, seed = is_handshake_body(body)
            if ok:
                target_cipher = XorCipher(seed)
                print(f"[cipher] target seed = 0x{seed:04X} ({seed})")
        # consume bytes the parser fully accepted
        consumed = 0
        for _off, plen, body in parse_frames(bytes(rx_buf)):
            consumed += plen + len(body)
        del rx_buf[:consumed]

    if target_cipher is None:
        print("Target never sent a 0x0807 handshake within timeout; aborting.", file=sys.stderr)
        sock.close()
        return 2

    # Phase 2: replay C->S frames, re-encrypting bodies.
    for i, dec_body in enumerate(decrypted_bodies):
        enc_body = target_cipher.transform(dec_body)
        frame = encode_frame(enc_body)
        sock.sendall(frame)
        op = opcode_of(dec_body)
        print(f"  >> [{op:04X}] payload_len={len(dec_body) - 2}  (sent {len(frame)} wire bytes)")
        if args.inter_frame_delay:
            time.sleep(args.inter_frame_delay)
        # interleave reads so server pushback doesn't pile up
        chunk = drain_once()
        if chunk:
            rx_buf.extend(chunk)
            consumed = 0
            for _off, plen, body in parse_frames(bytes(rx_buf)):
                op = opcode_of(body)
                pl = payload_of(body)
                note = decode_watch_frame(op, pl) if op in watch else ""
                print(f"  << [{op:04X}] payload_len={len(pl)}  {short_hex(pl)}" + (f"   {note}" if note else ""))
                consumed += plen + len(body)
            del rx_buf[:consumed]

    # Phase 3: final drain.
    end = time.monotonic() + args.read_timeout
    while time.monotonic() < end:
        chunk = drain_once()
        if not chunk:
            break
        rx_buf.extend(chunk)
    if rx_buf:
        consumed = 0
        for _off, plen, body in parse_frames(bytes(rx_buf)):
            op = opcode_of(body)
            pl = payload_of(body)
            note = decode_watch_frame(op, pl) if op in watch else ""
            print(f"  << [{op:04X}] payload_len={len(pl)}  {short_hex(pl)}" + (f"   {note}" if note else ""))
            consumed += plen + len(body)
        del rx_buf[:consumed]

    sock.close()
    print("[net] closed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
