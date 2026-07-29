"""
session_client.py — Drive Login -> WM through the proxy enough to make WM
emit NC_CHAR_LOGIN_ACK (0x1003), which the proxy's CharLoginAckRewriter rewrites.

Validated layout (FiestaLib-Reloaded PDB extract):
  PROTO_NC_USER_WORLDSELECT_ACK      sizeof=83
    @  0 worldstatus  u8
    @  1 ip           Name4  (16)
    @ 17 port         u16
    @ 19 validate_new u16[32]  (64 bytes -- the OTP)
  PROTO_NC_USER_LOGINWORLD_REQ       sizeof=320
    @  0 user         Name256Byte
    @256 validate_new u16[32]  (64 bytes -- where the OTP goes back in)
  PROTO_NC_CHAR_LOGIN_REQ            sizeof=1
    @  0 slot         u8       (PROTO_AVATARINFORMATION.slot)
  PROTO_NC_USER_LOGINWORLD_ACK       sizeof=3+
    @  0 worldmanager u16
    @  2 numofavatar  u8
    @  3 avatar[]     PROTO_AVATARINFORMATION (sizeof=130 each, .slot @26)

Strategy:
  Phase 1 (Login): replay captured Login C->S verbatim (the user/password/version
                   hash are all baked into those frames; re-encrypt with the
                   server's fresh seed). Read the live [0C0C] response,
                   extract validate_new[64 bytes] @19.
  Phase 2 (WM)   : take the captured [0C0F] LOGINWORLD_REQ body, overwrite
                   bytes @256..320 with the live OTP, send. Pipeline the
                   captured [080D] + [1001+slot] follow-ons. The slot byte
                   for [1001] is read from the live LOGINWORLD_ACK
                   avatar[0].slot (@26 inside the avatar struct, which
                   itself begins at payload@3 -> absolute payload@29).
                   Watch S->C for [1003] CHAR_LOGIN_ACK.
"""
from __future__ import annotations

import argparse
import collections
import socket
import sys
import time

import dpkt

from _fiesta_proto import (
    XorCipher,
    encode_frame,
    is_handshake_body,
    opcode_of,
    parse_frames,
    payload_of,
)


# ---------- pcap loading ----------

def load_streams(path: str):
    bufs = collections.defaultdict(bytearray)
    seqs: dict[tuple, int] = {}
    with open(path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        rdr = dpkt.pcapng.Reader(f) if magic == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(f)
        for _ts, raw in rdr:
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
    return {k: bytes(v) for k, v in bufs.items()}


def stream_pair(streams, capture_port):
    c2s_cands = [(k, v) for k, v in streams.items() if k[3] == capture_port]
    if not c2s_cands:
        raise SystemExit(f"No C->S stream for port {capture_port}")
    c2s_key, c2s = max(c2s_cands, key=lambda kv: len(kv[1]))
    s2c_key = (c2s_key[2], c2s_key[3], c2s_key[0], c2s_key[1])
    return c2s, streams.get(s2c_key, b"")


def first_handshake_seed(s2c):
    for _o, _p, body in parse_frames(s2c):
        ok, seed = is_handshake_body(body)
        if ok:
            return seed
    return None


def decrypted_bodies(c2s, seed):
    cipher = XorCipher(seed)
    return [(off, plen, cipher.transform(body)) for off, plen, body in parse_frames(c2s)]


# ---------- net helpers ----------

def connect(host, port, timeout=5.0):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def wait_for_handshake(sock, rx, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            raise RuntimeError("peer closed before handshake")
        rx.extend(chunk)
        for _o, _p, body in parse_frames(bytes(rx)):
            ok, seed = is_handshake_body(body)
            if ok:
                # consume the handshake bytes
                consumed = 0
                for _o2, plen, b in parse_frames(bytes(rx)):
                    consumed += plen + len(b)
                    if b is body:
                        break
                del rx[:consumed]
                return XorCipher(seed), seed
    raise RuntimeError("handshake timeout")


def drain(sock, rx, secs):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            return
        rx.extend(chunk)


def send_body(sock, cipher, body, label=""):
    enc = cipher.transform(body)
    sock.sendall(encode_frame(enc))
    op = opcode_of(body)
    print(f"  >> [{label}] [{op:04X}] payload_len={len(payload_of(body))}")


def parse_inbound(rx, label=""):
    """Parse and consume complete frames from rx. Return list of bodies."""
    bodies = []
    consumed = 0
    for _o, plen, body in parse_frames(bytes(rx)):
        bodies.append(body)
        consumed += plen + len(body)
        op = opcode_of(body)
        pl = payload_of(body)
        print(f"  << [{label}] [{op:04X}] payload_len={len(pl)}")
    del rx[:consumed]
    return bodies


# ---------- protocol constants ----------

OPCODE_WORLDSELECT_ACK  = 0x0C0C
OPCODE_LOGINWORLD_REQ   = 0x0C0F
OPCODE_LOGINWORLD_ACK   = 0x0C14
OPCODE_LOGINWORLDFAIL   = 0x0C15
OPCODE_CHAR_LOGIN_REQ   = 0x1001
OPCODE_CHAR_LOGIN_ACK   = 0x1003

OTP_LEN = 64
OTP_OFFSET_IN_WORLDSELECT_ACK = 19   # validate_new @19
OTP_OFFSET_IN_LOGINWORLD_REQ  = 256  # validate_new @256
AVATAR_INFO_OFFSET_IN_LOGINWORLD_ACK = 3
AVATAR_SLOT_OFFSET = 26  # PROTO_AVATARINFORMATION.slot @26


# ---------- phases ----------

def phase_login(host, port, capture_bodies):
    """Replay Login C->S, return (live OTP from [0C0C], the still-open socket).

    The Login socket is deliberately NOT closed here -- the caller owns it and
    closes it after the WM phase. A real client holds its Login connection
    open across world-enter; closing it early lets the login session / OTP
    expire before WM validates it (seen as WM LOGINWORLDFAIL 0x0044)."""
    print(f"[Login] dial {host}:{port}")
    sock = connect(host, port)
    try:
        rx = bytearray()
        cipher, seed = wait_for_handshake(sock, rx)
        print(f"[Login] target seed=0x{seed:04X}")

        for _off, _plen, body in capture_bodies:
            send_body(sock, cipher, body, label="Login")
            time.sleep(0.03)

        drain(sock, rx, 2.0)
        bodies = parse_inbound(rx, label="Login")

        for body in bodies:
            if opcode_of(body) == OPCODE_WORLDSELECT_ACK:
                pl = payload_of(body)
                if len(pl) < OTP_OFFSET_IN_WORLDSELECT_ACK + OTP_LEN:
                    raise RuntimeError(f"[0C0C] short: {len(pl)}")
                otp = bytes(pl[OTP_OFFSET_IN_WORLDSELECT_ACK:
                              OTP_OFFSET_IN_WORLDSELECT_ACK + OTP_LEN])
                print(f"[Login] live OTP first16: {otp[:16].hex()}")
                return otp, sock
        raise RuntimeError("Login: no [0C0C] in response")
    except BaseException:
        sock.close()
        raise


def phase_wm(host, port, capture_bodies, live_otp):
    """Send patched [0C0F], wait for [0C14], send [1001+slot], watch for [1003].
    Returns (zone_ep, sock, cipher) — WM socket is kept open so the Zone-side
    validation (Zone calls WM via S2S to confirm the incoming player) finds
    a live WM session. WM clears character state on disconnect."""
    print(f"[WM] dial {host}:{port}")
    sock = connect(host, port)
    keep_open = False
    nonlocal_wm_handle: list[int] = []
    try:
        rx = bytearray()
        cipher, seed = wait_for_handshake(sock, rx)
        print(f"[WM] target seed=0x{seed:04X}")

        # Find [0C0F] in capture and patch OTP @256
        loginworld_body = None
        gametime_body = None
        for _off, _plen, body in capture_bodies:
            op = opcode_of(body)
            if op == OPCODE_LOGINWORLD_REQ and loginworld_body is None:
                pl = bytearray(payload_of(body))
                pl[OTP_OFFSET_IN_LOGINWORLD_REQ:
                   OTP_OFFSET_IN_LOGINWORLD_REQ + OTP_LEN] = live_otp
                loginworld_body = bytes(body[:2]) + bytes(pl)
                print(f"[WM] patched OTP at @{OTP_OFFSET_IN_LOGINWORLD_REQ} of [0C0F]")
            elif op == 0x080D and gametime_body is None:
                gametime_body = body

        if loginworld_body is None:
            raise RuntimeError("WM: no [0C0F] in capture")

        send_body(sock, cipher, loginworld_body, label="WM")
        # Wait for [0C14] (or fail [0C15])
        slot = None
        zone_ep = None
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and slot is None:
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    raise RuntimeError("WM: closed before LOGINWORLD_ACK")
                rx.extend(chunk)
            except socket.timeout:
                continue
            for body in parse_inbound(rx, label="WM"):
                op = opcode_of(body)
                pl = payload_of(body)
                if op == OPCODE_LOGINWORLDFAIL:
                    err = pl[0] | (pl[1] << 8) if len(pl) >= 2 else -1
                    raise RuntimeError(f"WM rejected LOGINWORLD with err=0x{err:04X} ({err})")
                if op == OPCODE_LOGINWORLD_ACK:
                    if len(pl) < 3:
                        raise RuntimeError("LOGINWORLD_ACK too short")
                    nonlocal_wm_handle.append(pl[0] | (pl[1] << 8))
                    wm_handle = nonlocal_wm_handle[-1]
                    numofavatar = pl[2]
                    if numofavatar == 0:
                        raise RuntimeError("LOGINWORLD_ACK: numofavatar=0")
                    avatar_base = AVATAR_INFO_OFFSET_IN_LOGINWORLD_ACK
                    slot_byte_off = avatar_base + AVATAR_SLOT_OFFSET
                    if len(pl) <= slot_byte_off:
                        raise RuntimeError("LOGINWORLD_ACK: avatar slot beyond payload")
                    slot = pl[slot_byte_off]
                    chrregnum = pl[avatar_base] | (pl[avatar_base+1]<<8) | (pl[avatar_base+2]<<16) | (pl[avatar_base+3]<<24)
                    name = pl[avatar_base + 4: avatar_base + 24].split(b"\x00")[0].decode("ascii", "replace")
                    print(f"[WM] worldmanager handle={wm_handle}, avatar[0]: chrregnum={chrregnum} name='{name}' slot={slot}")

        if slot is None:
            raise RuntimeError("WM: no LOGINWORLD_ACK before timeout")

        # Send heartbeat + CHAR_LOGIN_REQ with the avatar's slot
        if gametime_body is not None:
            send_body(sock, cipher, gametime_body, label="WM")
        char_login = bytes([0x01, 0x10, slot])  # opcode 0x1001 LE + slot
        send_body(sock, cipher, char_login, label="WM")

        # Watch for [1003]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and zone_ep is None:
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                rx.extend(chunk)
            except socket.timeout:
                continue
            for body in parse_inbound(rx, label="WM"):
                op = opcode_of(body)
                pl = payload_of(body)
                if op == OPCODE_CHAR_LOGIN_ACK and len(pl) >= 18:
                    ip = pl[0:16].split(b"\x00", 1)[0].decode("ascii", "replace")
                    zp = pl[16] | (pl[17] << 8)
                    zone_ep = (ip, zp)
                    print(f"  *** [WM] [1003] CHAR_LOGIN_ACK -> {ip}:{zp}")
        keep_open = True
        wm_handle = nonlocal_wm_handle[-1] if nonlocal_wm_handle else 0
        return zone_ep, sock, cipher, wm_handle
    finally:
        if not keep_open:
            sock.close()


# ---------- main ----------

OPCODE_MAP_LOGIN_REQ = 0x1801
OPCODE_CHAR_CLIENT_BASE_CMD = 0x1038


def phase_zone(host, port, capture_bodies, wm_handle):
    """Connect to Zone, replay [1801] MAP_LOGIN_REQ with chardata.wldmanhandle
    patched to the live WM handle. Success = receive [1038]
    NC_CHAR_CLIENT_BASE_CMD (Zone confirming char load)."""
    print(f"[Zone] dial {host}:{port}")
    sock = connect(host, port)
    try:
        rx = bytearray()
        cipher, seed = wait_for_handshake(sock, rx)
        print(f"[Zone] target seed=0x{seed:04X}")

        login_body = None
        for _off, _plen, body in capture_bodies:
            if opcode_of(body) == OPCODE_MAP_LOGIN_REQ:
                login_body = body
                break
        if login_body is None:
            raise RuntimeError("Zone: no [1801] in capture")

        # Patch chardata.wldmanhandle (u16 @0 of payload) with live WM handle.
        pl = bytearray(payload_of(login_body))
        pl[0] = wm_handle & 0xFF
        pl[1] = (wm_handle >> 8) & 0xFF
        login_body = bytes(login_body[:2]) + bytes(pl)
        print(f"[Zone] patched [1801] chardata.wldmanhandle={wm_handle}")

        send_body(sock, cipher, login_body, label="Zone")

        got_basecmd = False
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not got_basecmd:
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                rx.extend(chunk)
            except socket.timeout:
                continue
            for body in parse_inbound(rx, label="Zone"):
                if opcode_of(body) == OPCODE_CHAR_CLIENT_BASE_CMD:
                    pl = payload_of(body)
                    # chrregnum u32 @0, name Name5 @4
                    name = pl[4:24].split(b"\x00", 1)[0].decode("ascii", "replace")
                    print(f"  *** [Zone] [1038] NC_CHAR_CLIENT_BASE_CMD name='{name}'")
                    got_basecmd = True
                    break
        return got_basecmd
    finally:
        sock.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("pcap")
    p.add_argument("--proxy-login", default="127.0.0.1:9010")
    p.add_argument("--proxy-wm", default="127.0.0.1:9013")
    p.add_argument("--proxy-zone", default="127.0.0.1:9019")
    p.add_argument("--login-user", default=None, help="override sUserName in the 0x0C5A login frame")
    p.add_argument("--login-pw-md5", default=None, help="override sPassword (MD5 hex) in the 0x0C5A login frame")
    args = p.parse_args()

    streams = load_streams(args.pcap)

    login_c2s, login_s2c = stream_pair(streams, 9010)
    login_seed = first_handshake_seed(login_s2c)
    if login_seed is None:
        raise SystemExit("Login capture has no handshake")
    login_bodies = decrypted_bodies(login_c2s, login_seed)
    print(f"[load] Login: {len(login_bodies)} C->S frames (capture seed=0x{login_seed:04X})")

    if args.login_user or args.login_pw_md5:
        for _i in range(len(login_bodies)):
            off, plen, body = login_bodies[_i]
            if opcode_of(body) == 0x0C5A and len(body) >= 2 + 296:
                pl = bytearray(payload_of(body))
                if args.login_user:
                    pl[0:260] = b"\x00" * 260
                    pl[0:len(args.login_user)] = args.login_user.encode("ascii")
                if args.login_pw_md5:
                    pw = args.login_pw_md5.strip().encode("ascii")
                    pl[260:296] = b"\x00" * 36
                    pl[260:260 + len(pw)] = pw
                login_bodies[_i] = (off, plen, bytes(body[:2]) + bytes(pl))
                print(f"[patch] login creds -> user={args.login_user}")

    wm_c2s, wm_s2c = stream_pair(streams, 9013)
    wm_seed = first_handshake_seed(wm_s2c)
    if wm_seed is None:
        raise SystemExit("WM capture has no handshake")
    wm_bodies = decrypted_bodies(wm_c2s, wm_seed)
    print(f"[load] WM: {len(wm_bodies)} C->S frames (capture seed=0x{wm_seed:04X})")

    lh, lp = args.proxy_login.rsplit(":", 1)
    live_otp, login_sock = phase_login(lh, int(lp), login_bodies)

    # Hold the Login socket open across the WM (and Zone) phases -- a real
    # client keeps its Login connection up through world-enter, and closing it
    # early lets the login session / OTP expire before WM validates it.
    try:
        wh, wp = args.proxy_wm.rsplit(":", 1)
        zone_ep, wm_sock, wm_cipher, wm_handle = phase_wm(wh, int(wp), wm_bodies, live_otp)
        if zone_ep is None:
            wm_sock.close()
            print("[chain] no [1003] received")
            return 1
        print(f"[chain] WM advertised zone (post-proxy-rewrite): {zone_ep[0]}:{zone_ep[1]}")

        zone_c2s, zone_s2c = stream_pair(streams, 9019)
        zone_seed = first_handshake_seed(zone_s2c)
        if zone_seed is None:
            wm_sock.close()
            raise SystemExit("Zone capture has no handshake")
        zone_bodies = decrypted_bodies(zone_c2s, zone_seed)
        print(f"[load] Zone: {len(zone_bodies)} C->S frames (capture seed=0x{zone_seed:04X})")

        try:
            zh, zp = args.proxy_zone.rsplit(":", 1)
            ok = phase_zone(zh, int(zp), zone_bodies, wm_handle)
        finally:
            # Send NORMALLOGOUT_CMD on WM before closing — matches captured tail.
            try:
                send_body(wm_sock, wm_cipher, bytes([0x18, 0x0C, 0x00]), label="WM")
            except Exception:
                pass
            wm_sock.close()

        if not ok:
            print("[chain] Zone did not return [1038] NC_CHAR_CLIENT_BASE_CMD")
            return 2
        print("[chain] DONE — Login -> WM -> Zone chain completed")
        return 0
    finally:
        login_sock.close()


if __name__ == "__main__":
    sys.exit(main())
