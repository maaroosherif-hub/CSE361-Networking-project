from __future__ import annotations

import struct
import time
from collections import namedtuple
from enum import IntEnum

# --- Constants ---
PROTOCOL_ID = 0xCD
VERSION = 1
HEADER_FMT = '!BBBBIQ'
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # Resolves to 16 bytes
MAX_PAYLOAD = 256
DEFAULT_PORT = 5005


class MsgType(IntEnum):
    HELLO = 0           # client -> server (INIT)
    HELLO_ACK = 1       # server -> client
    SYNC_REQ = 2        # client -> server, header timestamp = t1
    SYNC_RESP = 3       # server -> client, payload t1, t2, t3
    EXECUTE_AT = 4      # server -> client, deadline on server clock
    ACTION_CONFIRM = 5  # client -> server, execution report
    ERROR = 6           # either direction
    BYE = 7             # server -> client, run finished: exit cleanly


# Status values carried in ACTION_CONFIRM
STATUS_EXECUTED = 0
STATUS_DROPPED_LATE = 1

# Error codes carried in ERROR
ERR_BAD_MAGIC = 1
ERR_BAD_VERSION = 2
ERR_UNKNOWN_TYPE = 3
ERR_BAD_LENGTH = 4
ERR_UNKNOWN_CLIENT = 5

# Payload formats (after the 16-byte header)
SYNC_RESP_FMT = '!QQQ'           # t1, t2, t3
EXECUTE_AT_FMT = '!IQH'          # cmd_id, target_time_us, action_cmd
ACTION_CONFIRM_FMT = '!IQQqB'    # cmd_id, exec_time_us, true_exec_us, offset_us, status
ERROR_FMT = '!H'                 # error_code

SYNC_RESP_SIZE = struct.calcsize(SYNC_RESP_FMT)            # 24
EXECUTE_AT_SIZE = struct.calcsize(EXECUTE_AT_FMT)          # 14
ACTION_CONFIRM_SIZE = struct.calcsize(ACTION_CONFIRM_FMT)  # 29
ERROR_SIZE = struct.calcsize(ERROR_FMT)                    # 2


class ProtocolError(Exception):
    """Raised when parsing fails due to contract violations."""
    pass


def now_us() -> int:
    """Current time in microseconds from a high-resolution clock.

    perf_counter_ns() is precise on both Windows and Linux (time.time() only
    ticks every ~15.6 ms on Windows before Python 3.13). Its start point is
    arbitrary (time since boot), which is fine: clients measure their offset
    relative to the server, so any constant difference between clocks becomes
    part of the offset. On one machine, all processes read the same counter,
    which gives a shared "true" clock for measuring real divergence.
    """
    return time.perf_counter_ns() // 1000


# --- Parsed message shapes ---
# namedtuples are still tuples, so positional unpacking keeps working,
# but fields can also be read by name (msg.offset_us) to avoid order mistakes.
Hello = namedtuple('Hello', 'client_id seq ts')
HelloAck = namedtuple('HelloAck', 'seq ts')
SyncReq = namedtuple('SyncReq', 'client_id seq ts')
SyncResp = namedtuple('SyncResp', 'seq ts t1 t2 t3')
ExecuteAt = namedtuple('ExecuteAt', 'seq ts cmd_id target_time_us action_cmd')
ActionConfirm = namedtuple('ActionConfirm',
                           'client_id seq ts cmd_id exec_time_us true_exec_us offset_us status')
Error = namedtuple('Error', 'client_id seq ts error_code')
Bye = namedtuple('Bye', 'seq ts')


# --- Header Packing/Unpacking ---
def pack_header(msg_type: int, client_id: int, seq_num: int, timestamp: int) -> bytes:
    # Shift Version 4 bits left, then bitwise-OR with MsgType for the second byte
    version_msgtype = (VERSION << 4) | (msg_type & 0x0F)
    flags = 0  # Hardcoded to 0 for Phase 1
    return struct.pack(HEADER_FMT, PROTOCOL_ID, version_msgtype, client_id, flags, seq_num, timestamp)


def unpack_header(data: bytes) -> tuple:
    if len(data) < HEADER_SIZE:
        raise ProtocolError(f"Packet too short: {len(data)} bytes")

    magic, ver_type, client_id, flags, seq_num, timestamp = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])

    if magic != PROTOCOL_ID:
        raise ProtocolError(f"Invalid magic byte: {hex(magic)}")

    # Extract the high 4 bits for version, low 4 bits for msg_type
    version = ver_type >> 4
    msg_type = ver_type & 0x0F

    if version != VERSION:
        raise ProtocolError(f"Unknown version: {version}")

    try:
        msg_type_enum = MsgType(msg_type)
    except ValueError:
        raise ProtocolError(f"Unknown message type: {msg_type}")

    return msg_type_enum, client_id, seq_num, timestamp


def _check_payload_len(payload: bytes):
    if len(payload) > MAX_PAYLOAD:
        raise ProtocolError(f"Payload exceeds {MAX_PAYLOAD} bytes")


def _unpack_expect(data: bytes, expected: MsgType) -> tuple:
    """Unpack the header, verify it is the expected message type,
    and return (client_id, seq, ts, payload).

    Needed because HELLO, HELLO_ACK, SYNC_REQ and BYE have identical layouts
    (bare 16-byte header), so without this check one could be parsed as another.
    """
    msg_type, client_id, seq, ts = unpack_header(data)
    if msg_type != expected:
        raise ProtocolError(f"Expected {expected.name}, got {msg_type.name}")
    payload = data[HEADER_SIZE:]
    _check_payload_len(payload)
    return client_id, seq, ts, payload


def _expect_len(payload: bytes, size: int, name: str):
    if len(payload) != size:
        raise ProtocolError(f"{name} payload must be exactly {size} bytes, got {len(payload)}")


# --- Message Builders & Parsers ---

# 0 HELLO
def build_hello(client_id: int, seq_num: int, timestamp: int) -> bytes:
    return pack_header(MsgType.HELLO, client_id, seq_num, timestamp)


def parse_hello(data: bytes) -> Hello:
    client_id, seq, ts, payload = _unpack_expect(data, MsgType.HELLO)
    _expect_len(payload, 0, "HELLO")
    return Hello(client_id, seq, ts)


# 1 HELLO_ACK
def build_hello_ack(seq_num: int, timestamp: int) -> bytes:
    return pack_header(MsgType.HELLO_ACK, 0, seq_num, timestamp)


def parse_hello_ack(data: bytes) -> HelloAck:
    client_id, seq, ts, payload = _unpack_expect(data, MsgType.HELLO_ACK)
    _expect_len(payload, 0, "HELLO_ACK")
    return HelloAck(seq, ts)


# 2 SYNC_REQ
def build_sync_req(client_id: int, seq_num: int, timestamp: int) -> bytes:
    return pack_header(MsgType.SYNC_REQ, client_id, seq_num, timestamp)


def parse_sync_req(data: bytes) -> SyncReq:
    client_id, seq, ts, payload = _unpack_expect(data, MsgType.SYNC_REQ)
    _expect_len(payload, 0, "SYNC_REQ")
    return SyncReq(client_id, seq, ts)


# 3 SYNC_RESP
def build_sync_resp(seq_num: int, timestamp: int, t1: int, t2: int, t3: int) -> bytes:
    header = pack_header(MsgType.SYNC_RESP, 0, seq_num, timestamp)
    return header + struct.pack(SYNC_RESP_FMT, t1, t2, t3)


def parse_sync_resp(data: bytes) -> SyncResp:
    client_id, seq, ts, payload = _unpack_expect(data, MsgType.SYNC_RESP)
    _expect_len(payload, SYNC_RESP_SIZE, "SYNC_RESP")
    t1, t2, t3 = struct.unpack(SYNC_RESP_FMT, payload)
    return SyncResp(seq, ts, t1, t2, t3)


# 4 EXECUTE_AT
def build_execute_at(seq_num: int, timestamp: int, cmd_id: int, target_time_us: int, action_cmd: int) -> bytes:
    header = pack_header(MsgType.EXECUTE_AT, 0, seq_num, timestamp)
    return header + struct.pack(EXECUTE_AT_FMT, cmd_id, target_time_us, action_cmd)


def parse_execute_at(data: bytes) -> ExecuteAt:
    client_id, seq, ts, payload = _unpack_expect(data, MsgType.EXECUTE_AT)
    _expect_len(payload, EXECUTE_AT_SIZE, "EXECUTE_AT")
    cmd_id, target_time_us, action_cmd = struct.unpack(EXECUTE_AT_FMT, payload)
    return ExecuteAt(seq, ts, cmd_id, target_time_us, action_cmd)


# 5 ACTION_CONFIRM
def build_action_confirm(client_id: int, seq_num: int, timestamp: int, cmd_id: int,
                         exec_time_us: int, true_exec_us: int, offset_us: int, status: int) -> bytes:
    """exec_time_us: execution time converted to the server clock (exec_local + offset).
    true_exec_us: the client's unskewed now_us() at execution - ground truth used
    to measure real divergence, so a wrong offset cannot hide behind its own estimate.
    """
    header = pack_header(MsgType.ACTION_CONFIRM, client_id, seq_num, timestamp)
    payload = struct.pack(ACTION_CONFIRM_FMT, cmd_id, exec_time_us, true_exec_us, offset_us, status)
    return header + payload


def parse_action_confirm(data: bytes) -> ActionConfirm:
    client_id, seq, ts, payload = _unpack_expect(data, MsgType.ACTION_CONFIRM)
    _expect_len(payload, ACTION_CONFIRM_SIZE, "ACTION_CONFIRM")
    cmd_id, exec_time_us, true_exec_us, offset_us, status = struct.unpack(ACTION_CONFIRM_FMT, payload)
    return ActionConfirm(client_id, seq, ts, cmd_id, exec_time_us, true_exec_us, offset_us, status)


# 6 ERROR
def build_error(client_id: int, seq_num: int, timestamp: int, error_code: int) -> bytes:
    header = pack_header(MsgType.ERROR, client_id, seq_num, timestamp)
    return header + struct.pack(ERROR_FMT, error_code)


def parse_error(data: bytes) -> Error:
    client_id, seq, ts, payload = _unpack_expect(data, MsgType.ERROR)
    _expect_len(payload, ERROR_SIZE, "ERROR")
    (error_code,) = struct.unpack(ERROR_FMT, payload)
    return Error(client_id, seq, ts, error_code)


# 7 BYE
def build_bye(seq_num: int, timestamp: int) -> bytes:
    return pack_header(MsgType.BYE, 0, seq_num, timestamp)


def parse_bye(data: bytes) -> Bye:
    client_id, seq, ts, payload = _unpack_expect(data, MsgType.BYE)
    _expect_len(payload, 0, "BYE")
    return Bye(seq, ts)


# --- Dispatcher ---

_PARSERS = {
    MsgType.HELLO: parse_hello,
    MsgType.HELLO_ACK: parse_hello_ack,
    MsgType.SYNC_REQ: parse_sync_req,
    MsgType.SYNC_RESP: parse_sync_resp,
    MsgType.EXECUTE_AT: parse_execute_at,
    MsgType.ACTION_CONFIRM: parse_action_confirm,
    MsgType.ERROR: parse_error,
    MsgType.BYE: parse_bye,
}


def parse_packet(data: bytes) -> tuple:
    """Parse any CDDAP packet received from the socket.

    Returns (msg_type, fields) where fields is the namedtuple returned by the
    matching parse_* function. Raises ProtocolError on any malformed packet.
    The header is unpacked twice (here to peek, then inside the parser);
    that costs nothing for 16 bytes and keeps each parser usable on its own.
    """
    msg_type, _, _, _ = unpack_header(data)
    return msg_type, _PARSERS[msg_type](data)