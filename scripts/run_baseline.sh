#!/usr/bin/env bash
# Baseline (LAN) scenario on Linux/WSL, with pcap capture.
#   ./scripts/run_baseline.sh                 # default seed 42
#   ./scripts/run_baseline.sh --seed 7        # any run_baseline.py flag works
#   PYTHON=python3.14 ./scripts/run_baseline.sh
set -euo pipefail

cd "$(dirname "$0")/.."               # repo root, wherever the script is called from
PYTHON="${PYTHON:-python3}"

if ! command -v tcpdump >/dev/null 2>&1; then
    echo "tcpdump not found: sudo apt install tcpdump   (continuing without pcap)"
fi

exec "$PYTHON" scripts/run_baseline.py --pcap "$@"
