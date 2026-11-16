# CDDAP — Coordinated Deadline-Driven Action Protocol

CSE361 Computer Networks · Fall 2026 · Project 3

A UDP protocol where one **server** acts as the master clock and tells four
**clients** to perform an action at the same absolute moment. Each client's
clock disagrees with the server's, so before it can obey a deadline it measures
its clock **offset** and the network **round-trip time** (RTT), then executes
the command when its offset-corrected clock reaches the target.

**Target:** all clients execute within ±5 ms of each other on a clean LAN, and
±15 ms under network delay.

> **Status:** Phase 1 (Prototype) complete: server, client, baseline test and
> unit tests work. Netem scenarios (delay, jitter, loss) come in Phase 2.
> The submission README with run instructions is [`README.txt`](README.txt).

---

## Team

| Member | ID | Role | Owns | GitHub |
|---|---|---|---|---|
| Hamzah Elleithy | 24p0379 | A: Protocol & documents | `protocol.py`, tests, Mini-RFC, proposal | `@hamzahe06` |
| Abdulrahman Baher | 24p0263 | B: Server & automation | `server.py`, `logger.py`, baseline scripts | `@Abdulrahman2194` |
| Omar Sherif Abdelhalim | 24p0255 | C: Client & delivery | `client.py`, `README.txt`, demo video | `@maaroosherif-hub` |

---

## How it works

```
Client                                   Server
  HELLO            ──────────────────►   register client
                   ◄──────────────────   HELLO_ACK
  SYNC_REQ  (t1)   ──────────────────►   t2 = receive time
                   ◄──────────────────   SYNC_RESP (t1, t2, t3)   t3 = send time
  t4 = receive time
  ... repeats every second ...
                   ◄──────────────────   EXECUTE_AT (target time, server clock)
  wait, then fire
  ACTION_CONFIRM   ──────────────────►   compute divergence across clients
                   ◄──────────────────   BYE
```

From the four timestamps:

```
RTT    = (t4 - t1) - (t3 - t2)
offset = ((t2 - t1) + (t3 - t4)) / 2       # = server clock - client clock
local deadline = server target - offset
```

Each client keeps its last 8 samples and uses the offset from the one with the
**lowest RTT**: the least-delayed exchange has the least room for error.

### Header (16 bytes, network byte order, `struct` format `!BBBBIQ`)

| Offset | Field | Size | Notes |
|---|---|---|---|
| 0 | Protocol_ID | 1 B | magic `0xCD` |
| 1 | Version \| MsgType | 1 B | high 4 bits = version (1), low 4 bits = type |
| 2 | Client_ID | 1 B | 0 = server, 1–4 = clients |
| 3 | Flags | 1 B | reserved (0) |
| 4 | Seq_Num | 4 B | per sender, starts at 1 |
| 8 | Timestamp | 8 B | send time, µs, monotonic clock |

### Messages

| Type | Name | Direction | Payload |
|---|---|---|---|
| 0 | HELLO | client → server | none |
| 1 | HELLO_ACK | server → client | none |
| 2 | SYNC_REQ | client → server | none (header timestamp = t1) |
| 3 | SYNC_RESP | server → client | t1, t2, t3 (24 B) |
| 4 | EXECUTE_AT | server → client | cmd_id, target_us, action (14 B) |
| 5 | ACTION_CONFIRM | client → server | cmd_id, exec_us, true_exec_us, offset_us, status (29 B) |
| 6 | ERROR | either | error code (2 B) |
| 7 | BYE | server → client | none |

---

## Repository layout

```
cddap/
  protocol.py     header + message pack/parse, constants        (A)
  logger.py       CSV log of every packet sent/received         (B)
  server.py       time authority + command broadcaster         (B)
  client.py       sync, offset filter, deadline execution      (C)
tests/            unit tests for protocol.py                    (A)
scripts/          baseline test automation                      (B)
docs/             proposal and Mini-RFC                         (A)
results/          baseline_seed42/: the baseline run as evidence (B)
logs/             local test runs (not committed)
```

---

## Running it

**Requirements:** Python 3.10+ (developed on 3.14), standard library only.
Run every command from the repository root.

**1. Start the server**

```bash
python -m cddap.server --run-id demo
```

**2. Start four clients** (one terminal each). `--skew-ms` gives each client a
deliberately wrong clock, so the sync has real work to do:

```bash
python -m cddap.client --id 1 --skew-ms=0    --run-id demo
python -m cddap.client --id 2 --skew-ms=137  --run-id demo
python -m cddap.client --id 3 --skew-ms=-85  --run-id demo
python -m cddap.client --id 4 --skew-ms=250  --run-id demo
```

On Windows, use `py` instead of `python`. Use the `--skew-ms=-85` form (with
`=`) for negative values.

**3. Read the logs** in `logs/demo/`: `server.csv`, `client1.csv` … `client4.csv`.

### Baseline test (one command)

Starts the server and 4 clients with seeded clock skews, runs 10 commands plus
1 deliberately late command, and prints PASS or FAIL.

```bash
./scripts/run_baseline.sh          # Linux / WSL2, with pcap (needs tcpdump)
py scripts\run_baseline.py         # Windows, no pcap
```

Outputs go to `logs/<timestamp>_seed<seed>/`; one kept run is in
`results/baseline_seed42/`. Unit tests: `python -m unittest discover -s tests -v`.

### Command-line flags

| Program | Flag | Default | Meaning |
|---|---|---|---|
| server | `--host` | `127.0.0.1` | bind address (`0.0.0.0` for a real LAN) |
| server | `--port` | `5005` | UDP port |
| server | `--clients` | `4` | clients to wait for |
| server | `--run-id` | `manual` | log folder name |
| client | `--id` | required | client ID, 1–4 |
| client | `--skew-ms` | `0` | fake clock error in ms |
| client | `--server` | `127.0.0.1` | server address |
| client | `--port` | `5005` | server port |
| client | `--run-id` | required | log folder name |

---

## Team workflow

- **Never commit straight to `main`.** Branch from an up-to-date `main`:
  `git checkout main && git pull && git checkout -b <letter>/<feature>`
  (e.g. `b/baseline-script`, `c/deadline-exec`).
- Each person edits **their own files**. Changes to `protocol.py` go through A,
  because everyone depends on it.
- Open a **pull request**; another teammate reviews before merging.
- Commit messages say what changed: `server: answer SYNC_REQ with t2/t3`.
- Before a PR: pull `main` into your branch and run the code once.

---

## Phase 1 checklist

- [x] `protocol.py`: header, 8 message types, parser
- [x] `logger.py`: CSV packet log
- [x] Server: HELLO registration, SYNC responses
- [x] Client: HELLO with retry, sync with min-RTT offset filter
- [x] Server: EXECUTE_AT broadcast, ACTION_CONFIRM collection, `summary.csv`, BYE
- [x] Client: deadline execution, late-packet drop, ACTION_CONFIRM, exit on BYE
- [x] `run_baseline.sh` / `run_baseline.py` with pcap capture
- [x] Unit tests for `protocol.py`
- [x] Proposal (≤ 3 pages) and Mini-RFC sections 1–3
- [x] `README.txt` with run instructions
- [ ] Demo video link added to `README.txt`
