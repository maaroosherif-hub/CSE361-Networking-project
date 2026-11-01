from __future__ import annotations

import csv
import os
import time

from cddap.protocol import now_us

COLUMNS = ["time_us", "wall_time_us", "node", "direction", "msg_type",
           "seq", "client_id", "peer", "bytes", "note"]


class PacketLogger:
    """Writes one CSV row per packet sent or received.

    time_us      - protocol clock (now_us), the same clock as t1/t2/t3 in packets,
                   and never the client's skewed clock, so every node's log
                   lines up on one timeline.
    wall_time_us - normal wall-clock time, only for matching rows to the pcap
                   in Wireshark.
    """

    def __init__(self, run_id: str, node: str, log_dir: str = "logs"):
        self.node = node
        self.dir = os.path.join(log_dir, run_id)
        os.makedirs(self.dir, exist_ok=True)   # safe when 5 processes create it at once
        self.path = os.path.join(self.dir, f"{node}.csv")
        # newline="" stops Windows from inserting blank lines between CSV rows
        self._file = open(self.path, "w", newline="", encoding="utf-8")
        self._writer = csv.writer(self._file)
        self._writer.writerow(COLUMNS)
        self._file.flush()

    def log(self, direction: str, msg_type, seq: int, client_id: int,
            peer, nbytes: int, note: str = "") -> None:
        """direction: "SEND", "RECV" or "DROP". msg_type: MsgType or a string.
        peer: (ip, port) tuple from recvfrom/sendto, or a string."""
        if isinstance(peer, tuple):
            peer = f"{peer[0]}:{peer[1]}"
        type_name = getattr(msg_type, "name", str(msg_type))
        self._writer.writerow([now_us(), time.time_ns() // 1000, self.node,
                               direction, type_name, seq, client_id, peer,
                               nbytes, note])
        self._file.flush()   # a crash must not lose the last rows

    def close(self) -> None:
        if not self._file.closed:
            self._file.close()

    # allows: with PacketLogger(...) as log:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()