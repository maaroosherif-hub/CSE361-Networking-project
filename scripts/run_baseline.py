"""Run the CDDAP Baseline (LAN) scenario: 1 server + 4 clients on this machine.

    python scripts/run_baseline.py                 # Windows or Linux, no pcap
    sudo python3.14 scripts/run_baseline.py --pcap # Linux/WSL with tcpdump capture
    ./scripts/run_baseline.sh                      # Linux/WSL shortcut (pcap on)

Each client gets a deliberately wrong clock (--skew-ms), drawn from --seed, so
the run is reproducible: same seed -> same skews and same action codes.
Outputs go to <out-dir>/<YYYYmmdd-HHMMSS>_seed<seed>/.
"""
from __future__ import annotations

import argparse
import csv
import os
import platform
import random
import shutil
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def parse_args():
    p = argparse.ArgumentParser(description="CDDAP baseline experiment")
    p.add_argument("--seed", type=int, default=42, help="seeds clock skews and action codes")
    p.add_argument("--clients", type=int, default=4)
    p.add_argument("--commands", type=int, default=10)
    p.add_argument("--late-commands", type=int, default=1,
                   help="commands sent with an already-passed deadline (must be dropped)")
    p.add_argument("--lead-ms", type=int, default=500)
    p.add_argument("--interval-ms", type=int, default=1000)
    p.add_argument("--warmup-s", type=float, default=3.0)
    p.add_argument("--max-skew-ms", type=int, default=300, help="skews drawn from +-this")
    p.add_argument("--port", type=int, default=5005)
    p.add_argument("--out-dir", default="logs")
    p.add_argument("--pcap", action="store_true", help="capture with tcpdump (Linux, needs root)")
    p.add_argument("--iface", default="lo", help="capture interface (lo = loopback)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    os.chdir(REPO_ROOT)                      # so "-m cddap.server" works from anywhere
    py = sys.executable                      # children use the same Python as this script

    run_id = f"{time.strftime('%Y%m%d-%H%M%S')}_seed{args.seed}"
    run_dir = os.path.join(args.out_dir, run_id)
    os.makedirs(run_dir, exist_ok=True)

    rng = random.Random(args.seed)
    skews = [rng.randint(-args.max_skew_ms, args.max_skew_ms) for _ in range(args.clients)]

    with open(os.path.join(run_dir, "run_info.txt"), "w", encoding="utf-8") as f:
        f.write(f"run_id: {run_id}\n")
        f.write(f"scenario: baseline (no netem)\n")
        f.write(f"python: {platform.python_version()} ({py})\n")
        f.write(f"platform: {platform.platform()}\n")
        f.write(f"args: {vars(args)}\n")
        f.write(f"client skews (ms): {dict(zip(range(1, args.clients + 1), skews))}\n")

    procs = []
    tcpdump = None
    try:
        # ---- 1. packet capture (optional) ----
        if args.pcap:
            if not sys.platform.startswith("linux"):
                print("[baseline] --pcap needs Linux/WSL; continuing without capture")
            elif shutil.which("tcpdump") is None:
                print("[baseline] tcpdump not installed (sudo apt install tcpdump); no capture")
            else:
                # --immediate-mode: hand each packet over at once instead of in kernel
                # blocks, otherwise the last ~0.5 s (incl. BYE) is lost when tcpdump stops.
                # -U: write each packet to the file immediately.
                cmd = ["tcpdump", "-i", args.iface, "--immediate-mode", "-U",
                       "-w", os.path.join(run_dir, "baseline.pcap"),
                       "udp", "port", str(args.port)]
                if os.geteuid() != 0:
                    cmd = ["sudo"] + cmd     # asks for your password once
                tcpdump = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                time.sleep(1.5)              # give tcpdump time to start capturing
                if tcpdump.poll() is not None:
                    print("[baseline] tcpdump failed:", tcpdump.stderr.read().decode().strip())
                    tcpdump = None

        # ---- 2. server ----
        server = subprocess.Popen(
            [py, "-m", "cddap.server", "--port", str(args.port), "--clients", str(args.clients),
             "--commands", str(args.commands), "--late-commands", str(args.late_commands),
             "--lead-ms", str(args.lead_ms), "--interval-ms", str(args.interval_ms),
             "--warmup-s", str(args.warmup_s), "--seed", str(args.seed),
             "--run-id", run_id, "--log-dir", args.out_dir])
        procs.append(server)
        time.sleep(0.5)                      # let the server bind before clients send HELLO

        # ---- 3. clients ----
        for cid, skew in enumerate(skews, start=1):
            procs.append(subprocess.Popen(
                [py, "-m", "cddap.client", "--id", str(cid), f"--skew-ms={skew}",
                 "--port", str(args.port), "--run-id", run_id, "--log-dir", args.out_dir]))

        # ---- 4. wait: the server exits after BYE, clients exit on BYE ----
        expected_s = (args.warmup_s + (args.commands + args.late_commands)
                      * args.interval_ms / 1000 + 15)
        server.wait(timeout=expected_s)
        for p in procs[1:]:
            p.wait(timeout=15)
    except subprocess.TimeoutExpired:
        print("[baseline] a process did not finish in time; stopping everything")
    except KeyboardInterrupt:
        print("\n[baseline] interrupted")
    finally:
        for p in procs:                       # clean up whatever is still running
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        if tcpdump is not None:
            time.sleep(1.0)                   # let the last packets reach the file
            tcpdump.terminate()               # sudo forwards the signal to tcpdump
            try:
                tcpdump.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tcpdump.kill()

    return report(run_dir, procs)


def report(run_dir: str, procs) -> int:
    print(f"\n[baseline] outputs in {run_dir}:")
    for name in sorted(os.listdir(run_dir)):
        print(f"   {name}")

    summary = os.path.join(run_dir, "summary.csv")
    if not os.path.exists(summary):
        print("[baseline] FAIL: no summary.csv (server did not finish)")
        return 1
    with open(summary, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    normal = [r for r in rows if r["kind"] == "normal"]
    late = [r for r in rows if r["kind"] == "late"]
    passed = sum(r["within_5ms"] == "True" for r in normal)
    late_ok = all(r["executed"] == "0" and r["missing"] == "0" for r in late)
    exits = [p.returncode for p in procs]

    print(f"[baseline] normal commands within +-5 ms: {passed}/{len(normal)}")
    if late:
        print(f"[baseline] late commands dropped by every client: {'yes' if late_ok else 'NO'}")
    print(f"[baseline] process exit codes (server, clients): {exits}")
    ok = passed == len(normal) and late_ok and all(c == 0 for c in exits)
    print(f"[baseline] {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
