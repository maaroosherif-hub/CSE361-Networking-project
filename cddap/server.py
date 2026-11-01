from __future__ import annotations

import sys

if sys.version_info < (3, 10):
    sys.exit("CDDAP requires Python 3.10 or newer")

import argparse
import csv
import os
import random
import select
import socket
import statistics

from cddap.logger import PacketLogger
from cddap.protocol import (
    DEFAULT_PORT, ERR_UNKNOWN_CLIENT, STATUS_EXECUTED, MsgType, ProtocolError,
    build_bye, build_error, build_execute_at, build_hello_ack, build_sync_resp,
    now_us, parse_packet,
)

RECV_BUF = 2048          # larger than any valid packet; anything bigger is rejected by the parser
LOOP_TIMEOUT_S = 0.01    # select() wakes up at least every 10 ms, even with no traffic
BYE_REPEATS = 3          # UDP can lose a packet: send BYE a few times, clients ignore extras
BYE_GAP_US = 50_000
BASELINE_TOLERANCE_MS = 5.0   # spec: baseline clients execute within +-5 ms of each other

SUMMARY_COLUMNS = ["cmd_id", "kind", "action_cmd", "target_us", "executed", "dropped_late",
                   "missing", "divergence_true_ms", "divergence_est_ms", "max_abs_error_ms",
                   "within_5ms"]


class Command:
    """One EXECUTE_AT sent to every client, plus the confirmations that come back."""

    def __init__(self, cmd_id: int, target_us: int, action_cmd: int, kind: str, give_up_at_us: int):
        self.cmd_id = cmd_id
        self.target_us = target_us      # server clock
        self.action_cmd = action_cmd
        self.kind = kind                # "normal" or "late" (deadline already passed when sent)
        self.give_up_at_us = give_up_at_us
        self.confirms = {}              # client_id -> ActionConfirm


class Server:
    # states, in order
    WAITING_CLIENTS, WARMUP, COMMANDING, DRAINING, DONE = range(5)

    def __init__(self, args):
        self.args = args
        self.n_clients = args.clients
        self.clients: dict[int, tuple[str, int]] = {}   # client_id -> (ip, port)
        self.seq = 0
        self.log = PacketLogger(args.run_id, "server", args.log_dir)
        self.rng = random.Random(args.seed)              # deterministic action codes

        self.state = Server.WAITING_CLIENTS
        self.warmup_ends_us = 0
        self.next_cmd_us = 0
        self.cmd_ids_sent = 0
        self.total_cmds = args.commands + args.late_commands
        self.pending: dict[int, Command] = {}            # commands still collecting confirms
        self.finished: list[Command] = []
        self.bye_sent = 0
        self.next_bye_us = 0

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((args.host, args.port))
        print(f"[server] listening on {args.host}:{args.port}, expecting {self.n_clients} clients")

    # ---------- sending ----------
    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def send(self, data: bytes, addr, msg_type: MsgType, client_id: int, seq: int, note: str = ""):
        self.sock.sendto(data, addr)
        self.log.log("SEND", msg_type, seq, client_id, addr, len(data), note)

    def send_error(self, addr, cid: int, note: str):
        seq = self.next_seq()
        self.send(build_error(0, seq, now_us(), ERR_UNKNOWN_CLIENT), addr,
                  MsgType.ERROR, cid, seq, note)

    # ---------- receiving ----------
    def handle_packet(self, data: bytes, addr, t_recv: int):
        """t_recv = now_us() taken immediately after recvfrom (t2 for SYNC_REQ)."""
        try:
            msg_type, msg = parse_packet(data)
        except ProtocolError as e:
            # never crash on bad input: log it and ignore it
            self.log.log("DROP", "MALFORMED", 0, 0, addr, len(data), str(e))
            return

        cid = getattr(msg, "client_id", 0)
        self.log.log("RECV", msg_type, msg.seq, cid, addr, len(data))

        if msg_type == MsgType.HELLO:
            self.on_hello(msg, addr)
        elif msg_type == MsgType.SYNC_REQ:
            self.on_sync_req(msg, addr, t_recv)
        elif msg_type == MsgType.ACTION_CONFIRM:
            self.on_action_confirm(msg, addr)
        else:
            # valid packet, but not one a server should receive
            self.log.log("DROP", msg_type, msg.seq, cid, addr, len(data), "unexpected type for server")

    def on_hello(self, msg, addr):
        cid = msg.client_id
        if not 1 <= cid <= self.n_clients:
            self.send_error(addr, cid, f"client_id {cid} out of range")
            return

        known = self.clients.get(cid)
        if known is not None and known != addr:
            # same ID claimed from a different address: refuse instead of hijacking
            self.send_error(addr, cid, f"client_id {cid} already registered from {known}")
            return

        if known is None:
            self.clients[cid] = addr
            print(f"[server] client {cid} registered from {addr[0]}:{addr[1]} "
                  f"({len(self.clients)}/{self.n_clients})")

        # duplicate HELLO (our ACK was lost) gets a fresh ACK: HELLO is idempotent
        seq = self.next_seq()
        self.send(build_hello_ack(seq, now_us()), addr, MsgType.HELLO_ACK, cid, seq)

    def on_sync_req(self, msg, addr, t2: int):
        """Answer a clock-sync request.

        The client computes  RTT    = (t4 - t1) - (t3 - t2)
                             offset = ((t2 - t1) + (t3 - t4)) / 2
        Time spent between t2 and t3 is subtracted out exactly, so logging or
        other work in between does NOT hurt accuracy. What hurts is any gap
        between the packet arriving and t2, or between t3 and the packet
        leaving, because the formula cannot see those. Hence: t2 is taken
        right after recvfrom (in run), and t3 right before sendto (below).
        """
        cid = msg.client_id
        if self.clients.get(cid) != addr:
            # only registered clients may sync: they must send HELLO first
            self.send_error(addr, cid, "SYNC_REQ before HELLO")
            return

        t1 = msg.ts                      # client's send time, echoed back unchanged
        seq = self.next_seq()
        t3 = now_us()                    # as late as possible...
        data = build_sync_resp(seq, t3, t1, t2, t3)
        self.sock.sendto(data, addr)     # ...right before the packet leaves
        # log AFTER sending so the CSV write never sits between t3 and sendto
        self.log.log("SEND", MsgType.SYNC_RESP, seq, cid, addr, len(data),
                     f"t1={t1} t2={t2} t3={t3}")

    def on_action_confirm(self, msg, addr):
        cid = msg.client_id
        if self.clients.get(cid) != addr:
            self.send_error(addr, cid, "ACTION_CONFIRM from unregistered client")
            return
        cmd = self.pending.get(msg.cmd_id)
        if cmd is None:
            # unknown, or already finalized (a late duplicate): nothing to update
            self.log.log("DROP", MsgType.ACTION_CONFIRM, msg.seq, cid, addr, 0,
                         f"cmd {msg.cmd_id} not pending")
            return
        if cid in cmd.confirms:
            self.log.log("DROP", MsgType.ACTION_CONFIRM, msg.seq, cid, addr, 0,
                         f"duplicate confirm for cmd {msg.cmd_id}")
            return
        cmd.confirms[cid] = msg
        if len(cmd.confirms) == len(self.clients):
            self.finalize(cmd)

    # ---------- commands ----------
    def send_command(self, now: int):
        self.cmd_ids_sent += 1
        cmd_id = self.cmd_ids_sent
        is_late = cmd_id > self.args.commands
        lead_us = self.args.lead_ms * 1000
        # a "late" command carries a deadline that has already passed when it is sent:
        # every client must drop it and report STATUS_DROPPED_LATE
        target = now - lead_us if is_late else now + lead_us
        action = self.rng.randint(1, 0xFFFF)
        cmd = Command(cmd_id, target, action, "late" if is_late else "normal",
                      give_up_at_us=max(target, now) + self.args.confirm_timeout_ms * 1000)
        self.pending[cmd_id] = cmd

        for cid in sorted(self.clients):
            seq = self.next_seq()
            self.send(build_execute_at(seq, now_us(), cmd_id, target, action),
                      self.clients[cid], MsgType.EXECUTE_AT, cid, seq,
                      f"cmd {cmd_id} target={target} kind={cmd.kind}")
        print(f"[server] EXECUTE_AT cmd {cmd_id} ({cmd.kind}) sent, "
              f"target in {(target - now) / 1000:+.0f} ms")

    def finalize(self, cmd: Command):
        """All confirms in (or timed out): compute divergence and record the result."""
        del self.pending[cmd.cmd_id]
        self.finished.append(cmd)

        executed = [c for c in cmd.confirms.values() if c.status == STATUS_EXECUTED]
        dropped = len(cmd.confirms) - len(executed)
        missing = len(self.clients) - len(cmd.confirms)

        div_true = div_est = max_err = None
        if len(executed) >= 2:
            # divergence = latest execution - earliest execution, across clients.
            # true_exec_us is each client's UNSKEWED clock: on one machine all
            # processes share it, so this measures what really happened.
            true_times = [c.true_exec_us for c in executed]
            est_times = [c.exec_time_us for c in executed]
            div_true = (max(true_times) - min(true_times)) / 1000
            div_est = (max(est_times) - min(est_times)) / 1000
        if executed:
            max_err = max(abs(c.true_exec_us - cmd.target_us) for c in executed) / 1000

        cmd.result = {
            "cmd_id": cmd.cmd_id, "kind": cmd.kind, "action_cmd": cmd.action_cmd,
            "target_us": cmd.target_us, "executed": len(executed),
            "dropped_late": dropped, "missing": missing,
            "divergence_true_ms": f"{div_true:.3f}" if div_true is not None else "",
            "divergence_est_ms": f"{div_est:.3f}" if div_est is not None else "",
            "max_abs_error_ms": f"{max_err:.3f}" if max_err is not None else "",
            "within_5ms": ("" if cmd.kind == "late" or div_true is None
                           else str(div_true <= BASELINE_TOLERANCE_MS and missing == 0)),
        }
        if cmd.kind == "late":
            print(f"[server] cmd {cmd.cmd_id} (late): {dropped} dropped, "
                  f"{len(executed)} executed, {missing} missing")
        else:
            shown = f"{div_true:.3f} ms" if div_true is not None else "n/a"
            print(f"[server] cmd {cmd.cmd_id}: divergence {shown}, "
                  f"{len(executed)} executed, {dropped} dropped, {missing} missing")

    # ---------- timers ----------
    def tick(self, now: int):
        """Called every loop iteration: moves the state machine forward."""
        if self.state == Server.WAITING_CLIENTS and len(self.clients) == self.n_clients:
            self.state = Server.WARMUP
            self.warmup_ends_us = now + int(self.args.warmup_s * 1_000_000)
            print(f"[server] all clients registered, warm-up {self.args.warmup_s} s")

        elif self.state == Server.WARMUP and now >= self.warmup_ends_us:
            self.state = Server.COMMANDING
            self.next_cmd_us = now

        elif self.state == Server.COMMANDING:
            if now >= self.next_cmd_us:
                self.send_command(now)
                self.next_cmd_us = now + self.args.interval_ms * 1000
                if self.cmd_ids_sent == self.total_cmds:
                    self.state = Server.DRAINING

        if self.state in (Server.COMMANDING, Server.DRAINING):
            for cmd in list(self.pending.values()):
                if now >= cmd.give_up_at_us:
                    self.finalize(cmd)       # some confirms never came: count them missing
            if self.state == Server.DRAINING and not self.pending:
                self.state = Server.DONE
                self.next_bye_us = now

        if self.state == Server.DONE and self.bye_sent < BYE_REPEATS and now >= self.next_bye_us:
            for cid in sorted(self.clients):
                seq = self.next_seq()
                self.send(build_bye(seq, now_us()), self.clients[cid], MsgType.BYE, cid, seq)
            self.bye_sent += 1
            self.next_bye_us = now + BYE_GAP_US

    def finished_all(self) -> bool:
        return self.state == Server.DONE and self.bye_sent >= BYE_REPEATS

    # ---------- results ----------
    def write_summary(self):
        if not self.finished:
            return
        path = os.path.join(self.log.dir, "summary.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=SUMMARY_COLUMNS)
            w.writeheader()
            for cmd in sorted(self.finished, key=lambda c: c.cmd_id):
                w.writerow(cmd.result)

        normal = [float(c.result["divergence_true_ms"]) for c in self.finished
                  if c.kind == "normal" and c.result["divergence_true_ms"]]
        print(f"[server] summary written to {path}")
        if normal:
            print(f"[server] divergence over {len(normal)} commands: "
                  f"min {min(normal):.3f} / median {statistics.median(normal):.3f} / "
                  f"max {max(normal):.3f} ms")

    # ---------- main loop ----------
    def run(self):
        try:
            while not self.finished_all():
                readable, _, _ = select.select([self.sock], [], [], LOOP_TIMEOUT_S)
                if readable:
                    try:
                        data, addr = self.sock.recvfrom(RECV_BUF)
                        t_recv = now_us()    # t2: stamped before ANY other work
                    except ConnectionResetError:
                        # Windows only: a previous sendto hit a closed client port.
                        # Harmless for UDP; ignore so one dead client can't kill the server.
                        continue
                    self.handle_packet(data, addr, t_recv)
                self.tick(now_us())
        except KeyboardInterrupt:
            print("\n[server] stopped by user")
        finally:
            self.write_summary()
            self.sock.close()
            self.log.close()


def parse_args():
    p = argparse.ArgumentParser(description="CDDAP server (time authority + command broadcaster)")
    p.add_argument("--host", default="127.0.0.1", help="bind address (0.0.0.0 for LAN)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--clients", type=int, default=4, help="clients to wait for")
    p.add_argument("--commands", type=int, default=10, help="normal EXECUTE_AT commands")
    p.add_argument("--late-commands", type=int, default=0,
                   help="extra commands sent with an already-passed deadline (late-drop test)")
    p.add_argument("--lead-ms", type=int, default=500, help="deadline = send time + lead (300-1000)")
    p.add_argument("--interval-ms", type=int, default=1000, help="gap between commands")
    p.add_argument("--warmup-s", type=float, default=3.0, help="sync time after all clients join")
    p.add_argument("--confirm-timeout-ms", type=int, default=1000,
                   help="wait this long after the deadline for missing confirms")
    p.add_argument("--seed", type=int, default=42, help="seed for action codes")
    p.add_argument("--run-id", default="manual", help="log folder name")
    p.add_argument("--log-dir", default="logs")
    args = p.parse_args()
    if not 300 <= args.lead_ms <= 1000:
        p.error("--lead-ms must be 300-1000 (spec)")
    return args


def main():
    Server(parse_args()).run()


if __name__ == "__main__":
    main()
