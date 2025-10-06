# envia un GET a coap://<host>:<port>/<path>.
# python client_get.py --host <DIRECCION IP> --path sensor

import argparse
import os
import random
import socket
import struct
import sys

COAP_VER = 1
TYPE_CON = 0
OPT_URI_PATH = 11

def _encode_uvar(n):
    if n < 13:
        return n, b""
    elif n < 269:
        return 13, bytes([n - 13])
    else:
        n2 = n - 269
        return 14, struct.pack("!H", n2)

def build_get(host, port, path, tkl=4):
    # header
    token = os.urandom(tkl)
    mid = random.randint(0, 0xFFFF)
    first = ((COAP_VER & 0x03) << 6) | ((TYPE_CON & 0x03) << 4) | (tkl & 0x0F)
    code = 0x01  # GET
    header = struct.pack("!BBH", first, code, mid)

    # options: Uri-Path segments
    opts = b""
    last_opt_num = 0
    segments = [seg for seg in path.split('/') if seg]
    for seg in segments:
        opt_num = OPT_URI_PATH
        delta = opt_num - last_opt_num
        seg_bytes = seg.encode("utf-8")
        nib_d, ext_d = _encode_uvar(delta)
        nib_l, ext_l = _encode_uvar(len(seg_bytes))
        opts += bytes([(nib_d << 4) | nib_l]) + ext_d + ext_l + seg_bytes
        last_opt_num = opt_num

    # No payload (GET)
    pkt = header + token + opts
    return pkt, token, mid

def parse_response(data):
    if len(data) < 4:
        return None
    first, code, mid = struct.unpack("!BBH", data[:4])
    ver = (first >> 6) & 0x03
    typ = (first >> 4) & 0x03
    tkl = first & 0x0F
    if ver != COAP_VER or len(data) < 4 + tkl or tkl > 8:
        return None
    token = data[4:4+tkl]
    p = 4 + tkl
    end = len(data)

    last_opt = 0
    while p < end:
        if data[p] == 0xFF:
            p += 1
            break
        if p >= end:
            break
        byte = data[p]
        p += 1
        delta4 = (byte >> 4) & 0x0F
        len4   =  byte       & 0x0F

        def read_ext(nibble):
            nonlocal p
            if nibble < 13:
                return nibble
            elif nibble == 13:
                if p >= end: raise ValueError("bad opt len (13)")
                v = data[p]; p += 1
                return 13 + v
            elif nibble == 14:
                if p + 1 >= end: raise ValueError("bad opt len (14)")
                v = (data[p] << 8) | data[p+1]; p += 2
                return 269 + v
            else:
                raise ValueError("nibble 15 reserved")

        try:
            d = read_ext(delta4)
            l = read_ext(len4)
        except Exception:
            return None

        optnum = last_opt + d
        if p + l > end:
            return None
        p += l
        last_opt = optnum

    payload = data[p:end] if p <= end else b""
    return {"ver": ver, "type": typ, "tkl": tkl, "code": code, "mid": mid,
            "token": token, "payload": payload}

def code_to_str(code):
    cclass = code >> 5
    detail = code & 0x1F
    return f"{cclass}.{detail:02d}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="IP")
    ap.add_argument("--port", type=int, default=5683, help="Puerto UDP (default 5683)")
    ap.add_argument("--path", default="sensor", help="Ruta (default: sensor)")
    ap.add_argument("--timeout", type=float, default=5.0, help="Timeout (s)")
    args = ap.parse_args()

    pkt, token, mid = build_get(args.host, args.port, args.path)
    addr = (args.host, args.port)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(args.timeout)
        try:
            s.sendto(pkt, addr)
            data, src = s.recvfrom(1500)
        except socket.timeout:
            print(f"[TIMEOUT] GET coap://{args.host}/{args.path} (>{args.timeout:.1f}s)")
            sys.exit(1)

    resp = parse_response(data)
    if not resp:
        print("[ERROR] Respuesta CoAP invalida")
        sys.exit(2)

    cstr = code_to_str(resp["code"])
    try:
        text = resp["payload"].decode("utf-8", errors="replace")
    except Exception:
        text = str(resp["payload"])

    print(f"coap://{args.host}/{args.path}")
    print(f"[OK] GET -> {cstr} | {text}")

if __name__ == "__main__":
    main()
