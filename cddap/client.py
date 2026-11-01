from __future__ import annotations

import sys

if sys.version_info < (3, 10):
    sys.exit("CDDAP requires Python 3.10 or newer")

import argparse
import heapq
import itertools
import select
import socket
from collections import deque

from cddap.logger import PacketLogger
from cddap.protocol import (
    now_us, DEFAULT_PORT, MsgType, ProtocolError,
    STATUS_DROPPED_LATE, STATUS_EXECUTED,
    build_action_confirm, build_hello, build_sync_req, parse_packet,
)

HELLO_RETRY_US = 500_000   # wait 500 ms for HELLO_ACK before resending
HELLO_MAX_TRIES = 5        # give up after 5 HELLOs
SYNC_TIMEOUT_US = 500_000  # a SYNC_RESP later than this counts as lost

SYNC_WINDOW = 8              # keep the last 8 samples
SYNC_BURST_GAP_US = 50_000   # initial burst: 8 rounds, 50 ms apart
SYNC_PERIOD_US = 1_000_000   # after that: one round every 1 s while the link is calm...
SYNC_FAST_PERIOD_US = 250_000    # ...or every 250 ms while RTT is jumpy
RTT_JITTER_THRESHOLD_US = 2_000  # window RTT spread above this = "jumpy"

SPIN_US = 20_000         # stop sleeping this long before a deadline and busy-wait the rest.
                         # select()/sleep can overshoot by up to ~15 ms on Windows, so
                         # the margin must be bigger than that.
SERVER_SILENT_EXIT_US = 10_000_000   # no packet from the server for 10 s -> assume it is gone
MAX_WAIT_S = 0.05        # never block longer than this, so timers are checked often


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

    def full(self):
        return len(self.samples) == self.samples.maxlen

    def rtt_spread_us(self):
        rtts = [s[0] for s in self.samples]
        return max(rtts) - min(rtts) if rtts else 0


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
                        help="run folder name, logs go to <log-dir>/<run-id>/")
    parser.add_argument("--log-dir", type=str, default="logs")
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


def check_packet(log, data, addr, server_addr):
    """Validate one received datagram. Returns (msg_type, msg), or None after
    logging a DROP for malformed packets and packets from strangers."""
    if addr != server_addr:
        log.log("DROP", "?", "", "", addr, len(data), "not from server")
        return None
    try:
        msg_type, msg = parse_packet(data)
    except ProtocolError as e:
        log.log("DROP", "?", "", "", addr, len(data), f"malformed: {e}")
        return None
    log.log("RECV", msg_type, msg.seq, 0, addr, len(data))
    return msg_type, msg


def recv_packet(sock, log, deadline_us, local_clock_us, server_addr):
    """Wait for one valid packet from the server, logging everything that arrives.
    Returns (msg_type, msg, recv_time_us), or None if the deadline passed.
    Malformed packets and packets from strangers are logged as DROP and skipped."""
    while True:
        got = recv_until(sock, deadline_us, local_clock_us)
        if got is None:
            return None
        data, addr, recv_time_us = got
        checked = check_packet(log, data, addr, server_addr)
        if checked is not None:
            return (*checked, recv_time_us)


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


class Client:
    """After registration, everything runs in ONE event loop (run):
    wait for a packet with a timeout, handle it, then check timers.
    That way a sync exchange, a pending deadline and a new command can all be
    in progress at once, and no packet is ever skipped while waiting.

    States: SYNCING (window not full yet) -> READY (offset trusted)
            READY -> ARMED (a command is waiting for its deadline) -> READY
            any -> DONE on BYE (or when the server goes silent)
    """

    def __init__(self, args, sock, log, server_addr, seq, local_clock_us):
        self.id = args.id
        self.sock, self.log = sock, log
        self.server_addr = server_addr
        self.seq = seq
        self.clock = local_clock_us
        self.filt = OffsetFilter()

        self.sync_t1 = None              # t1 of the outstanding SYNC_REQ, if any
        self.sync_deadline = 0
        self.next_sync_at = self.clock() # start the burst immediately
        self.sync_period = SYNC_BURST_GAP_US

        self.armed = []                  # heap of (target_server_us, cmd_id, action_cmd)
        self.seen_cmds = set()           # duplicate EXECUTE_AT suppression
        self.last_heard = self.clock()
        self.done = False
        self.executed = 0
        self.misses = 0

    # ---------- state ----------
    def state(self):
        if self.done:
            return "DONE"
        if self.armed:
            return "ARMED"
        return "READY" if self.filt.full() else "SYNCING"

    def offset_us(self):
        best = self.filt.best()
        return best[1] if best else None

    # ---------- sync ----------
    def start_sync(self):
        s = next(self.seq)
        self.sync_t1 = self.clock()                       # t1: client send time
        send_packet(self.sock, self.log, build_sync_req(self.id, s, self.sync_t1),
                    self.server_addr, MsgType.SYNC_REQ, s, self.id)
        self.sync_deadline = self.sync_t1 + SYNC_TIMEOUT_US

    def on_sync_resp(self, msg, t4):
        """Sign convention: offset = server_clock - client_clock.
        A client whose clock is 137 ms AHEAD gets offset = -137000 us,
        and converts server time to local time with: local = server - offset."""
        if self.sync_t1 is None or msg.t1 != self.sync_t1:
            # reply to an OLDER request (or one we gave up on): pairing it would be garbage
            self.log.log("DROP", MsgType.SYNC_RESP, msg.seq, 0, self.server_addr, 0, "stale SYNC_RESP")
            return
        t1, t2, t3 = self.sync_t1, msg.t2, msg.t3
        self.sync_t1 = None
        rtt_us = (t4 - t1) - (t3 - t2)
        offset_us = ((t2 - t1) + (t3 - t4)) // 2

        was_full = self.filt.full()
        self.filt.add(rtt_us, offset_us)
        best_rtt, best_off = self.filt.best()
        self.log.log("SYNC", "OFFSET", msg.seq, self.id, self.server_addr, 0,
                     f"rtt={rtt_us} offset={offset_us} best_offset={best_off} best_rtt={best_rtt}")
        if self.filt.full() and not was_full:
            print(f"[client {self.id}] READY, offset = {best_off / 1000:+.3f} ms "
                  f"(min RTT {best_rtt} us)")

    def schedule_next_sync(self, now):
        """Original mechanism #2: adaptive sync rate.
        Burst while filling the window, then resync every 1 s on a calm link,
        or every 250 ms when the RTTs in the window spread out (jitter), so the
        filter gets fresh low-RTT samples exactly when they are hardest to find."""
        if not self.filt.full():
            period = SYNC_BURST_GAP_US
        elif self.filt.rtt_spread_us() > RTT_JITTER_THRESHOLD_US:
            period = SYNC_FAST_PERIOD_US
        else:
            period = SYNC_PERIOD_US
        if period != self.sync_period and self.filt.full():
            self.log.log("SYNC", "RATE", "", self.id, "", 0, f"sync period -> {period // 1000} ms")
        self.sync_period = period
        self.next_sync_at = now + period

    # ---------- commands ----------
    def on_execute_at(self, msg):
        if msg.cmd_id in self.seen_cmds:
            self.log.log("DROP", MsgType.EXECUTE_AT, msg.seq, 0, self.server_addr, 0,
                         f"duplicate cmd {msg.cmd_id}")
            return
        self.seen_cmds.add(msg.cmd_id)

        offset = self.offset_us()
        if offset is None:
            # no clock estimate yet: cannot place this deadline at all
            self.drop_late(msg.cmd_id, "no offset yet")
            return

        target_local = msg.target_time_us - offset      # local = server - offset
        remaining = target_local - self.clock()
        if remaining <= 0:
            # spec: a command whose deadline has already passed is dropped, never executed
            self.drop_late(msg.cmd_id, f"deadline passed {-remaining / 1000:.1f} ms ago")
            return
        heapq.heappush(self.armed, (msg.target_time_us, msg.cmd_id, msg.action_cmd))
        self.log.log("ARM", MsgType.EXECUTE_AT, msg.seq, self.id, self.server_addr, 0,
                     f"cmd {msg.cmd_id} fires in {remaining / 1000:.1f} ms")

    def drop_late(self, cmd_id, why):
        self.misses += 1
        print(f"[client {self.id}] cmd {cmd_id} DROPPED: {why}")
        self.log.log("DROP", MsgType.EXECUTE_AT, "", self.id, self.server_addr, 0,
                     f"deadline miss cmd {cmd_id}: {why}")
        self.confirm(cmd_id, 0, now_us(), STATUS_DROPPED_LATE)

    def fire_due_commands(self):
        """Fire every armed command whose deadline is within SPIN_US.
        The deadline is recomputed with the LATEST offset, so resyncs that
        happened while the command waited are used."""
        while self.armed:
            target_server, cmd_id, action = self.armed[0]
            offset = self.offset_us()
            target_local = target_server - offset
            if target_local - self.clock() > SPIN_US:
                return                                   # not yet: keep sleeping
            heapq.heappop(self.armed)
            while self.clock() < target_local:           # busy-wait the last stretch
                pass
            exec_local = self.clock()
            true_exec = now_us()                         # unskewed: ground truth for divergence
            # --- the "action" itself is simulated: print + log ---
            self.executed += 1
            error_ms = (exec_local - target_local) / 1000
            print(f"[client {self.id}] EXECUTED cmd {cmd_id} (action {action}) "
                  f"{error_ms:+.3f} ms from local target")
            self.confirm(cmd_id, exec_local + offset, true_exec, STATUS_EXECUTED)

    def confirm(self, cmd_id, exec_server_us, true_exec_us, status):
        s = next(self.seq)
        offset = self.offset_us() or 0
        pkt = build_action_confirm(self.id, s, self.clock(), cmd_id,
                                   max(exec_server_us, 0), true_exec_us, offset, status)
        send_packet(self.sock, self.log, pkt, self.server_addr, MsgType.ACTION_CONFIRM, s,
                    self.id, note=f"cmd {cmd_id} status {status} exec={exec_server_us}")

    # ---------- event loop ----------
    def handle(self, msg_type, msg, t_recv):
        self.last_heard = self.clock()
        if msg_type == MsgType.SYNC_RESP:
            self.on_sync_resp(msg, t_recv)
        elif msg_type == MsgType.EXECUTE_AT:
            self.on_execute_at(msg)
        elif msg_type == MsgType.BYE:
            print(f"[client {self.id}] BYE received")
            self.done = True
        elif msg_type == MsgType.ERROR:
            print(f"[client {self.id}] ERROR from server: code {msg.error_code}")
        # HELLO_ACK duplicates and anything else: already logged as RECV, nothing to do

    def read_ready_packet(self):
        """select() said a packet is waiting: read it without blocking."""
        try:
            data, addr = self.sock.recvfrom(2048)
            t_recv = self.clock()        # t4 for SYNC_RESP: stamped before any other work
        except (BlockingIOError, ConnectionResetError):
            # nothing there after all / Windows ICMP "port unreachable": ignore
            return
        checked = check_packet(self.log, data, addr, self.server_addr)
        if checked is not None:
            self.handle(*checked, t_recv)

    def next_wakeup(self, now):
        """How long select() may sleep before some timer needs attention."""
        times = [self.next_sync_at, now + int(MAX_WAIT_S * 1_000_000)]
        if self.sync_t1 is not None:
            times.append(self.sync_deadline)
        if self.armed:
            times.append(self.armed[0][0] - self.offset_us() - SPIN_US)
        return max(0, min(times) - now)

    def run(self):
        while not self.done:
            now = self.clock()
            wait_s = self.next_wakeup(now) / 1_000_000
            readable, _, _ = select.select([self.sock], [], [], wait_s)
            if readable:
                self.read_ready_packet()

            now = self.clock()
            if self.sync_t1 is not None and now >= self.sync_deadline:
                self.log.log("SYNC", "TIMEOUT", "", self.id, self.server_addr, 0, "SYNC_RESP lost")
                self.sync_t1 = None                       # give up; the next round replaces it
            if self.sync_t1 is None and now >= self.next_sync_at:
                self.start_sync()
                self.schedule_next_sync(now)
            self.fire_due_commands()
            if now - self.last_heard > SERVER_SILENT_EXIT_US:
                print(f"[client {self.id}] server silent for "
                      f"{SERVER_SILENT_EXIT_US // 1_000_000} s, exiting")
                return 2
        print(f"[client {self.id}] done: {self.executed} executed, {self.misses} dropped late")
        return 0


def main():
    args = parse_args()
    skew_us = args.skew_ms * 1000          # 137 ms -> 137000 us

    def local_clock_us():
        return now_us() + skew_us          # this client's (deliberately wrong) clock

    server_addr = (args.server, args.port)
    seq = itertools.count(1)               # per-sender Seq_Num, starts at 1

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    log = PacketLogger(args.run_id, node=f"client{args.id}", log_dir=args.log_dir)
    try:
        if not do_hello(sock, log, server_addr, args.id, seq, local_clock_us):
            print(f"[client {args.id}] no HELLO_ACK after {HELLO_MAX_TRIES} tries, giving up")
            return 1
        print(f"[client {args.id}] registered with server {server_addr}")
        sock.setblocking(False)            # from here on, select() decides when to read
        return Client(args, sock, log, server_addr, seq, local_clock_us).run()
    except KeyboardInterrupt:
        print(f"\n[client {args.id}] stopped by user")
        return 130
    finally:
        sock.close()
        log.close()


if __name__ == "__main__":
    sys.exit(main())
