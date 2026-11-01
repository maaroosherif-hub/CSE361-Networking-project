from __future__ import annotations

import sys

if sys.version_info < (3, 10):
    sys.exit("CDDAP requires Python 3.10 or newer")

import argparse
import select
import socket

from cddap.logger import PacketLogger
from cddap.protocol import (
    DEFAULT_PORT, ERR_UNKNOWN_CLIENT, MsgType, ProtocolError,
    build_error, build_hello_ack, now_us, parse_packet,
)

RECV_BUF = 2048          # larger than any valid packet; anything bigger is rejected by the parser
LOOP_TIMEOUT_S = 0.01    # select() wakes up at least every 10 ms, even with no traffic


class Server:
    def __init__(self, host: str, port: int, n_clients: int, run_id: str, log_dir: str):
        self.n_clients = n_clients
        self.clients: dict[int, tuple[str, int]] = {}   # client_id -> (ip, port)
        self.seq = 0
        self.log = PacketLogger(run_id, "server", log_dir)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        print(f"[server] listening on {host}:{port}, expecting {n_clients} clients")

    # ---------- sending ----------
    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def send(self, data: bytes, addr, msg_type: MsgType, client_id: int, seq: int, note: str = ""):
        self.sock.sendto(data, addr)
        self.log.log("SEND", msg_type, seq, client_id, addr, len(data), note)

    # ---------- receiving ----------
    def handle_packet(self, data: bytes, addr):
        try:
            msg_type, msg = parse_packet(data)
        except ProtocolError as e:
            # never crash on bad input: log it and ignore it
            self.log.log("DROP", "MALFORMED", 0, 0, addr, len(data), str(e))
            return

        self.log.log("RECV", msg_type, msg.seq, getattr(msg, "client_id", 0), addr, len(data))

        if msg_type == MsgType.HELLO:
            self.on_hello(msg, addr)
        else:
            # valid packet, but not one this step handles yet (or not one a server should receive)
            self.log.log("DROP", msg_type, msg.seq, getattr(msg, "client_id", 0), addr,
                         len(data), "unexpected type for server")

    def on_hello(self, msg, addr):
        cid = msg.client_id
        if not 1 <= cid <= self.n_clients:
            seq = self.next_seq()
            self.send(build_error(0, seq, now_us(), ERR_UNKNOWN_CLIENT), addr,
                      MsgType.ERROR, cid, seq, f"client_id {cid} out of range")
            return

        known = self.clients.get(cid)
        if known is not None and known != addr:
            # same ID claimed from a different address: refuse instead of hijacking
            seq = self.next_seq()
            self.send(build_error(0, seq, now_us(), ERR_UNKNOWN_CLIENT), addr,
                      MsgType.ERROR, cid, seq, f"client_id {cid} already registered from {known}")
            return

        if known is None:
            self.clients[cid] = addr
            print(f"[server] client {cid} registered from {addr[0]}:{addr[1]} "
                  f"({len(self.clients)}/{self.n_clients})")

        # duplicate HELLO (our ACK was lost) gets a fresh ACK: HELLO is idempotent
        seq = self.next_seq()
        self.send(build_hello_ack(seq, now_us()), addr, MsgType.HELLO_ACK, cid, seq)

    # ---------- main loop ----------
    def run(self):
        try:
            while True:
                readable, _, _ = select.select([self.sock], [], [], LOOP_TIMEOUT_S)
                if readable:
                    try:
                        data, addr = self.sock.recvfrom(RECV_BUF)
                    except ConnectionResetError:
                        # Windows only: a previous sendto hit a closed client port.
                        # Harmless for UDP; ignore so one dead client can't kill the server.
                        continue
                    self.handle_packet(data, addr)
                # later steps: timers (warm-up, command schedule, confirm timeouts) go here
        except KeyboardInterrupt:
            print("\n[server] stopped by user")
        finally:
            self.sock.close()
            self.log.close()


def main():
    p = argparse.ArgumentParser(description="CDDAP server (time authority + command broadcaster)")
    p.add_argument("--host", default="127.0.0.1", help="bind address (0.0.0.0 for LAN)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--clients", type=int, default=4)
    p.add_argument("--run-id", default="manual")
    p.add_argument("--log-dir", default="logs")
    args = p.parse_args()

    Server(args.host, args.port, args.clients, args.run_id, args.log_dir).run()


if __name__ == "__main__":
    main()