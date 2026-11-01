"""Throwaway test client for developing the server before the real client exists.

Usage (from the repo root):
    py -m scripts.fake_client --id 1
    py -m scripts.fake_client --id 9          # out of range -> expect ERROR
"""
from __future__ import annotations

import argparse
import socket

from cddap.protocol import (DEFAULT_PORT, MsgType, ProtocolError,
                            build_hello, now_us, parse_packet)

p = argparse.ArgumentParser()
p.add_argument("--id", type=int, default=1)
p.add_argument("--server", default="127.0.0.1")
p.add_argument("--port", type=int, default=DEFAULT_PORT)
args = p.parse_args()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1.0)
sock.sendto(build_hello(args.id, 1, now_us()), (args.server, args.port))
print(f"[fake {args.id}] sent HELLO")

try:
    data, addr = sock.recvfrom(2048)
    msg_type, msg = parse_packet(data)
    print(f"[fake {args.id}] got {msg_type.name}: {msg}")
except socket.timeout:
    print(f"[fake {args.id}] no reply within 1 s (is the server running?)")
except ProtocolError as e:
    print(f"[fake {args.id}] malformed reply: {e}")
except ConnectionResetError:
    print(f"[fake {args.id}] server port closed (Windows reports this as a reset)")
finally:
    sock.close()