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
    """Returns the current time in microseconds."""
    return int(time.time() * 1_000_000)

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

# --- Message Builders & Parsers ---

# 0 HELLO
def build_hello(client_id: int, seq_num: int, timestamp: int) -> bytes:
    return pack_header(MsgType.HELLO, client_id, seq_num, timestamp)

def parse_hello(data: bytes) -> tuple:
    msg_type, client_id, seq, ts = unpack_header(data)
    payload = data[HEADER_SIZE:]
    _check_payload_len(payload)
    if payload:
        raise ProtocolError("HELLO should have no payload")
    return client_id, seq, ts

# 1 HELLO_ACK
def build_hello_ack(seq_num: int, timestamp: int) -> bytes:
    return pack_header(MsgType.HELLO_ACK, 0, seq_num, timestamp)

def parse_hello_ack(data: bytes) -> tuple:
    msg_type, client_id, seq, ts = unpack_header(data)
    payload = data[HEADER_SIZE:]
    _check_payload_len(payload)
    if payload:
        raise ProtocolError("HELLO_ACK should have no payload")
    return seq, ts

# 2 SYNC_REQ
def build_sync_req(client_id: int, seq_num: int, timestamp: int) -> bytes:
    return pack_header(MsgType.SYNC_REQ, client_id, seq_num, timestamp)

def parse_sync_req(data: bytes) -> tuple:
    msg_type, client_id, seq, ts = unpack_header(data)
    payload = data[HEADER_SIZE:]
    _check_payload_len(payload)
    if payload:
        raise ProtocolError("SYNC_REQ should have no payload")
    return client_id, seq, ts

# 3 SYNC_RESP
def build_sync_resp(seq_num: int, timestamp: int, t1: int, t2: int, t3: int) -> bytes:
    header = pack_header(MsgType.SYNC_RESP, 0, seq_num, timestamp)
    payload = struct.pack('!QQQ', t1, t2, t3)
    return header + payload

def parse_sync_resp(data: bytes) -> tuple:
    msg_type, client_id, seq, ts = unpack_header(data)
    payload = data[HEADER_SIZE:]
    _check_payload_len(payload)
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
    msg_type, client_id, seq, ts = unpack_header(data)
    payload = data[HEADER_SIZE:]
    _check_payload_len(payload)
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
    msg_type, client_id, seq, ts = unpack_header(data)
    payload = data[HEADER_SIZE:]
    _check_payload_len(payload)
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
    msg_type, client_id, seq, ts = unpack_header(data)
    payload = data[HEADER_SIZE:]
    _check_payload_len(payload)
    if len(payload) != 2:
        raise ProtocolError("ERROR payload must be exactly 2 bytes")
    (error_code,) = struct.unpack('!H', payload)
    return client_id, seq, ts, error_code