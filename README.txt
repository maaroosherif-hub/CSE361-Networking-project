CDDAP - Coordinated Deadline-Driven Action Protocol
CSE361 Computer Networks, Fall 2026 - Project 3 - Phase 1 submission

Team:
  Member A - Hamzah Elleithy   (24p0379)  - GitHub: hamzahe06         - protocol & documents
  Member B - Abdulrahman Baher (24p0263) - GitHub: Abdulrahman2194   - server & automation
  Member C - Omar Sherif Abdelhalim (24p0255) - GitHub: maaroosherif-hub - client & delivery

DEMO VIDEO (5 min): [PASTE LINK HERE - access: anyone with the link can view]


1. WHAT THIS IS
---------------
A UDP protocol in which one server (the master clock) tells 4 clients to run an
action at the same absolute time. Each client measures its clock offset and the
round-trip time with a 4-timestamp exchange (t1-t4), converts each EXECUTE_AT
deadline to its own clock, and executes it. Commands that arrive after their
deadline are dropped and reported. Full specification: docs/mini_rfc_v1.pdf.


2. REQUIREMENTS
---------------
- Python 3.10 or newer, standard library only (developed on 3.14).
  Tested on Windows 11 and Linux.
- Optional, for the packet capture: Linux or WSL2 with tcpdump
      sudo apt install tcpdump
- Run every command below from the repository root folder.
  On Windows, type "py" instead of "python3".


3. RUN THE BASELINE TEST (recommended)
--------------------------------------
One command starts the server and 4 clients, runs 10 commands plus 1
deliberately late command, then checks the results.

  Linux / WSL, with pcap capture (asks for your sudo password once):
      ./scripts/run_baseline.sh
      (with a specific Python: PYTHON=python3.14 ./scripts/run_baseline.sh)

  Windows (no capture):
      py scripts\run_baseline.py

  Options (both ways):  --seed 42  --commands 10  --late-commands 1
                        --lead-ms 500  --interval-ms 1000  --warmup-s 3

The same --seed always gives the same client clock skews and action codes.
The script ends with PASS or FAIL:
  PASS = every normal command executed by all 4 clients within +-5 ms of each
         other, the late command dropped by all 4, and all processes exited 0.


4. OUTPUTS
----------
Each run creates  logs/<YYYYmmdd-HHMMSS>_seed<seed>/  containing:
  run_info.txt    Python version, OS, arguments, client skews
  server.csv      every packet the server sent/received (+ drops)
  client1-4.csv   same for each client (+ sync results, armed commands)
  summary.csv     one row per command: divergence, executed/dropped/missing
  baseline.pcap   packet capture (Linux/WSL only) - open in Wireshark,
                  filter: udp.port == 5005

CSV columns (server.csv, clientN.csv):
  time_us       protocol clock in microseconds (same clock as packet timestamps)
  wall_time_us  normal clock time, to match rows against the pcap
  node, direction (SEND/RECV/DROP/SYNC/ARM), msg_type, seq, client_id,
  peer, bytes, note

summary.csv columns:
  divergence_true_ms  latest minus earliest execution, measured on the shared
                      unskewed clock (the real result)
  divergence_est_ms   the same, from the clients' own estimates
  max_abs_error_ms    worst client distance from the deadline
  within_5ms          True if divergence <= 5 ms and no client missing

A complete example run (CSV logs, summary.csv, pcap) is included in
results/baseline_seed42/.


5. RUN BY HAND (one terminal each)
----------------------------------
      python3 -m cddap.server --run-id demo
      python3 -m cddap.client --id 1 --skew-ms=0   --run-id demo
      python3 -m cddap.client --id 2 --skew-ms=137 --run-id demo
      python3 -m cddap.client --id 3 --skew-ms=-85 --run-id demo
      python3 -m cddap.client --id 4 --skew-ms=250 --run-id demo

Use the "--skew-ms=-85" form (with "=") for negative values.

Server flags:
  --host 127.0.0.1    bind address (0.0.0.0 for a real network)
  --port 5005         UDP port
  --clients 4         clients to wait for before starting
  --commands 10       normal EXECUTE_AT commands
  --late-commands 0   extra commands whose deadline has already passed
  --lead-ms 500       deadline = send time + lead (300-1000)
  --interval-ms 1000  gap between commands
  --warmup-s 3        sync time after the last client joins
  --confirm-timeout-ms 1000   wait after a deadline for missing confirms
  --seed 42           seed for action codes
  --run-id manual     log folder name
  --log-dir logs

Client flags:
  --id N              client id, 1-4 (required)
  --skew-ms N         artificial clock error in ms (default 0)
  --server 127.0.0.1  server address
  --port 5005         server port
  --run-id NAME       log folder name (required, same as the server's)
  --log-dir logs


6. UNIT TESTS
-------------
      python3 -m unittest discover -s tests -v


7. REPOSITORY LAYOUT
--------------------
  cddap/protocol.py    header + message formats, pack/parse (16-byte header)
  cddap/logger.py      CSV packet logger
  cddap/server.py      time authority, command broadcaster, divergence summary
  cddap/client.py      sync (min-RTT filter, adaptive rate), deadline execution
  tests/               unit tests for protocol.py
  scripts/             run_baseline.py (any OS), run_baseline.sh (Linux/WSL)
  docs/                proposal.pdf, mini_rfc_v1.pdf (sections 1-3)
  results/             one complete baseline run (CSV + summary + pcap)


8. NETWORK IMPAIRMENT (netem)
-----------------------------
Phase 1 covers the baseline scenario only (no impairment). The netem
scenarios (delay, jitter, loss) are added in Phase 2.
