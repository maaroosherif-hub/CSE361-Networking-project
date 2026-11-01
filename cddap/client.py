import argparse
import itertools
import socket
import time
from collections import deque

from cddap.logger import PacketLogger
from cddap.protocol import (
    now_us, DEFAULT_PORT, MsgType, ProtocolError,
    build_hello, build_sync_req, parse_packet,
)

HELLO_RETRY_US = 500_000   # wait 500 ms for HELLO_ACK before resending
HELLO_MAX_TRIES = 5        # give up after 5 HELLOs
SYNC_TIMEOUT_US = 500_000  # a SYNC_RESP later than this counts as lost

SYNC_WINDOW = 8              # keep the last 8 samples
SYNC_BURST_GAP_US = 50_000   # initial burst: 8 rounds, 50 ms apart
SYNC_PERIOD_US = 1_000_000   # after that: one round every 1 s


class OffsetFilter:
    """Original mechanism #1: min-RTT-filtered offset.

    Keeps the last SYNC_WINDOW (rtt, offset) samples and trusts the one with the
    lowest RTT. Why: the offset formula assumes the path takes equally long in
    both directions. Extra delay almost always lands on ONE direction (a queue,
    a scheduler pause), and it shifts the offset by half that delay. A low RTT
    means there was little extra delay on either leg, so little room for error.
    """

    def __init__(self, size=SYNC_WINDOW):
        self.samples = deque(maxlen=size)   # oldest drops out automatically

    def add(self, rtt_us, offset_us):
        self.samples.append((rtt_us, offset_us))

    def best(self):
        """(rtt_us, offset_us) of the lowest-RTT sample, or None if empty."""
        if not self.samples:
            return None
        return min(self.samples, key=lambda s: s[0])


def parse_args():
    parser = argparse.ArgumentParser(description="CDDAP client")
    parser.add_argument("--id", type=int, required=True, choices=[1, 2, 3, 4],
                        help="client id (1-4)")
    parser.add_argument("--skew-ms", type=int, default=0,
                        help="fake clock error in ms, added to this client's clock")
    parser.add_argument("--server", type=str, default="127.0.0.1",
                        help="server IP address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="server UDP port")
    parser.add_argument("--run-id", type=str, required=True,
                        help="run folder name, logs go to logs/<run-id>/")
    return parser.parse_args()


def send_packet(sock, log, pkt, addr, msg_type, seq, client_id, note=""):
    """sendto() + one SEND row in the log. Every packet goes through here."""
    sock.sendto(pkt, addr)
    log.log("SEND", msg_type, seq, client_id, addr, len(pkt), note)


def recv_until(sock, deadline_us, local_clock_us):
    """Wait for ONE packet, but never past deadline_us (local clock).
    Returns (data, addr, recv_time_us), or None if the deadline passed first.
    recv_time_us is read the instant recvfrom returns - before any parsing or
    logging - because that work would otherwise be counted as network delay."""
    remaining_us = deadline_us - local_clock_us()
    if remaining_us <= 0:
        return None
    sock.settimeout(remaining_us / 1_000_000)   # settimeout wants seconds
    try:
        data, addr = sock.recvfrom(2048)
        return data, addr, local_clock_us()
    except socket.timeout:
        return None
    except ConnectionResetError:
        # Windows only: server port closed -> ICMP "port unreachable" shows up
        # as an error on the next recvfrom. Treat it like "no reply yet".
        return None


def recv_packet(sock, log, deadline_us, local_clock_us, server_addr):
    """Wait for one valid packet from the server, logging everything that arrives.
    Returns (msg_type, msg, recv_time_us), or None if the deadline passed.
    Malformed packets and packets from strangers are logged as DROP and skipped."""
    while True:
        got = recv_until(sock, deadline_us, local_clock_us)
        if got is None:
            return None
        data, addr, recv_time_us = got
        if addr != server_addr:
            log.log("DROP", "?", "", "", addr, len(data), "not from server")
            continue
        try:
            msg_type, msg = parse_packet(data)
        except ProtocolError as e:
            log.log("DROP", "?", "", "", addr, len(data), f"malformed: {e}")
            continue
        log.log("RECV", msg_type, msg.seq, 0, addr, len(data))
        return msg_type, msg, recv_time_us


def do_hello(sock, log, server_addr, client_id, seq, local_clock_us):
    """Send HELLO, wait for HELLO_ACK. Retry every 500 ms, max 5 tries.
    Returns True when the server acknowledged us."""
    for attempt in range(1, HELLO_MAX_TRIES + 1):
        s = next(seq)
        send_packet(sock, log, build_hello(client_id, s, local_clock_us()),
                    server_addr, MsgType.HELLO, s, client_id,
                    note=f"try {attempt}/{HELLO_MAX_TRIES}")
        print(f"[client {client_id}] HELLO sent (try {attempt}/{HELLO_MAX_TRIES})")

        deadline_us = local_clock_us() + HELLO_RETRY_US
        while True:
            got = recv_packet(sock, log, deadline_us, local_clock_us, server_addr)
            if got is None:
                break                       # 500 ms passed -> resend
            msg_type, msg, _ = got
            if msg_type == MsgType.HELLO_ACK:
                print(f"[client {client_id}] HELLO_ACK received (server seq {msg.seq})")
                return True
            # any other type before we're registered: ignore and keep waiting
    return False


def do_sync_round(sock, log, server_addr, client_id, seq, local_clock_us):
    """One 4-timestamp exchange. Returns (rtt_us, offset_us), or None on timeout.

    Sign convention: offset = server_clock - client_clock.
    A client whose clock is 137 ms AHEAD gets offset = -137000 us,
    and converts server time to local time with: local = server - offset.
    """
    s = next(seq)
    t1 = local_clock_us()                      # client send time
    send_packet(sock, log, build_sync_req(client_id, s, t1),
                server_addr, MsgType.SYNC_REQ, s, client_id)

    deadline_us = local_clock_us() + SYNC_TIMEOUT_US
    while True:
        got = recv_packet(sock, log, deadline_us, local_clock_us, server_addr)
        if got is None:
            return None                        # reply lost or too slow
        msg_type, msg, t4 = got                # t4 = client receive time
        if msg_type != MsgType.SYNC_RESP:
            continue                           # not for us right now
        if msg.t1 != t1:
            # reply to an OLDER request: pairing it with this t1 would be garbage
            log.log("DROP", msg_type, msg.seq, 0, server_addr, 0, "stale SYNC_RESP")
            continue
        t2, t3 = msg.t2, msg.t3                # server receive / reply times
        rtt_us = (t4 - t1) - (t3 - t2)
        offset_us = ((t2 - t1) + (t3 - t4)) // 2
        return rtt_us, offset_us


def main():
    args = parse_args()
    skew_us = args.skew_ms * 1000          # 137 ms -> 137000 µs

    def local_clock_us():
        return now_us() + skew_us          # this client's (deliberately wrong) clock

    server_addr = (args.server, args.port)
    seq = itertools.count(1)               # per-sender Seq_Num, starts at 1

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    log = PacketLogger(args.run_id, node=f"client{args.id}")
    try:
        if not do_hello(sock, log, server_addr, args.id, seq, local_clock_us):
            print(f"[client {args.id}] no HELLO_ACK after {HELLO_MAX_TRIES} tries, giving up")
            return
        print(f"[client {args.id}] registered with server {server_addr}")

        filt = OffsetFilter()

        def sync_once():
            result = do_sync_round(sock, log, server_addr, args.id, seq, local_clock_us)
            if result is None:
                print(f"[client {args.id}] sync timeout")
                return
            filt.add(*result)
            rtt_us, raw_us = result
            best_rtt, best_off = filt.best()
            print(f"[client {args.id}] raw: RTT {rtt_us:6d} us  offset {raw_us / 1000:+9.3f} ms"
                  f"   | using: offset {best_off / 1000:+9.3f} ms (RTT {best_rtt} us)")

        # initial burst: fill the window fast before we trust any offset
        for _ in range(SYNC_WINDOW):
            sync_once()
            time.sleep(SYNC_BURST_GAP_US / 1_000_000)
        print(f"[client {args.id}] READY, offset = {filt.best()[1] / 1000:+.3f} ms")

        # Step D test: periodic resync for a few seconds.
        # Step E/F replace this loop with one that also handles EXECUTE_AT.
        for _ in range(6):
            time.sleep(SYNC_PERIOD_US / 1_000_000)
            sync_once()
    finally:
        sock.close()
        log.close()


if __name__ == "__main__":
    main()