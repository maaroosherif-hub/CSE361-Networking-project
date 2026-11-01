import struct
import time
from enum import IntEnum

# --- Constants ---
PROTOCOL_ID = 0xCD
VERSION = 1
HEADER_FMT = '!BBBBIQ'
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # Resolves to 16 bytes
MAX_PAYLOAD = 256
DEFAULT_PORT = 5005

class MsgType(IntEnum):
    HELLO = 0
    HELLO_ACK = 1
    SYNC_REQ = 2
    SYNC_RESP = 3
    EXECUTE_AT = 4
    ACTION_CONFIRM = 5
    ERROR = 6

class ProtocolError(Exception):
    """Raised when parsing fails due to contract violations."""
    pass

def now_us() -> int:
    """Current time in microseconds from a high-resolution clock.

    perf_counter_ns() is precise on both Windows and Linux (time.time() only
    ticks every ~15.6 ms on Windows before Python 3.13). Its start point is
    arbitrary, which is fine: clients measure their offset relative to the
    server, so any constant difference between clocks becomes part of the offset.
    """
    return time.perf_counter_ns() // 1000

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

    Needed because HELLO, HELLO_ACK and SYNC_REQ have identical layouts
    (bare 16-byte header), so without this check one could be parsed as another.
    """
    msg_type, client_id, seq, ts = unpack_header(data)
    if msg_type != expected:
        raise ProtocolError(f"Expected {expected.name}, got {msg_type.name}")
    payload = data[HEADER_SIZE:]
    _check_payload_len(payload)
    return client_id, seq, ts, payload

# --- Message Builders & Parsers ---

# 0 HELLO
def build_hello(client_id: int, seq_num: int, timestamp: int) -> bytes:
    return pack_header(MsgType.HELLO, client_id, seq_num, timestamp)

def parse_hello(data: bytes) -> tuple:
    client_id, seq, ts, payload = _unpack_expect(data, MsgType.HELLO)
    if payload:
        raise ProtocolError("HELLO should have no payload")
    return client_id, seq, ts

# 1 HELLO_ACK
def build_hello_ack(seq_num: int, timestamp: int) -> bytes:
    return pack_header(MsgType.HELLO_ACK, 0, seq_num, timestamp)

def parse_hello_ack(data: bytes) -> tuple:
    client_id, seq, ts, payload = _unpack_expect(data, MsgType.HELLO_ACK)
    if payload:
        raise ProtocolError("HELLO_ACK should have no payload")
    return seq, ts

# 2 SYNC_REQ
def build_sync_req(client_id: int, seq_num: int, timestamp: int) -> bytes:
    return pack_header(MsgType.SYNC_REQ, client_id, seq_num, timestamp)

def parse_sync_req(data: bytes) -> tuple:
    client_id, seq, ts, payload = _unpack_expect(data, MsgType.SYNC_REQ)
    if payload:
        raise ProtocolError("SYNC_REQ should have no payload")
    return client_id, seq, ts

# 3 SYNC_RESP
def build_sync_resp(seq_num: int, timestamp: int, t1: int, t2: int, t3: int) -> bytes:
    header = pack_header(MsgType.SYNC_RESP, 0, seq_num, timestamp)
    payload = struct.pack('!QQQ', t1, t2, t3)
    return header + payload

def parse_sync_resp(data: bytes) -> tuple:
    client_id, seq, ts, payload = _unpack_expect(data, MsgType.SYNC_RESP)
    if len(payload) != 24:
        raise ProtocolError("SYNC_RESP payload must be exactly 24 bytes")
    t1, t2, t3 = struct.unpack('!QQQ', payload)
    return seq, ts, t1, t2, t3

# 4 EXECUTE_AT
def build_execute_at(seq_num: int, timestamp: int, cmd_id: int, target_time_us: int, action_cmd: int) -> bytes:
    header = pack_header(MsgType.EXECUTE_AT, 0, seq_num, timestamp)
    payload = struct.pack('!IQH', cmd_id, target_time_us, action_cmd)
    return header + payload

def parse_execute_at(data: bytes) -> tuple:
    client_id, seq, ts, payload = _unpack_expect(data, MsgType.EXECUTE_AT)
    if len(payload) != 14:
        raise ProtocolError("EXECUTE_AT payload must be exactly 14 bytes")
    cmd_id, target_time_us, action_cmd = struct.unpack('!IQH', payload)
    return seq, ts, cmd_id, target_time_us, action_cmd

# 5 ACTION_CONFIRM
def build_action_confirm(client_id: int, seq_num: int, timestamp: int, cmd_id: int, exec_time_us: int, offset_us: int, status: int) -> bytes:
    header = pack_header(MsgType.ACTION_CONFIRM, client_id, seq_num, timestamp)
    payload = struct.pack('!IQqB', cmd_id, exec_time_us, offset_us, status)
    return header + payload

def parse_action_confirm(data: bytes) -> tuple:
    client_id, seq, ts, payload = _unpack_expect(data, MsgType.ACTION_CONFIRM)
    if len(payload) != 21:
        raise ProtocolError("ACTION_CONFIRM payload must be exactly 21 bytes")
    cmd_id, exec_time_us, offset_us, status = struct.unpack('!IQqB', payload)
    return client_id, seq, ts, cmd_id, exec_time_us, offset_us, status

# 6 ERROR
def build_error(client_id: int, seq_num: int, timestamp: int, error_code: int) -> bytes:
    header = pack_header(MsgType.ERROR, client_id, seq_num, timestamp)
    payload = struct.pack('!H', error_code)
    return header + payload

def parse_error(data: bytes) -> tuple:
    client_id, seq, ts, payload = _unpack_expect(data, MsgType.ERROR)
    if len(payload) != 2:
        raise ProtocolError("ERROR payload must be exactly 2 bytes")
    (error_code,) = struct.unpack('!H', payload)
    return client_id, seq, ts, error_code

# --- Dispatcher ---

_PARSERS = {
    MsgType.HELLO: parse_hello,
    MsgType.HELLO_ACK: parse_hello_ack,
    MsgType.SYNC_REQ: parse_sync_req,
    MsgType.SYNC_RESP: parse_sync_resp,
    MsgType.EXECUTE_AT: parse_execute_at,
    MsgType.ACTION_CONFIRM: parse_action_confirm,
    MsgType.ERROR: parse_error,
}

def parse_packet(data: bytes) -> tuple:
    """Parse any CDDAP packet received from the socket.

    Returns (msg_type, fields) where fields is the tuple returned by the
    matching parse_* function. Raises ProtocolError on any malformed packet.
    The header is unpacked twice (here to peek, then inside the parser);
    that costs nothing for 16 bytes and keeps each parser usable on its own.
    """
    msg_type, _, _, _ = unpack_header(data)
    return msg_type, _PARSERS[msg_type](data)