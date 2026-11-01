"""Unit tests for cddap/protocol.py.   Run:  python -m unittest discover -s tests -v"""
from __future__ import annotations

import struct
import unittest

from cddap import protocol as P
from cddap.protocol import MsgType, ProtocolError


class TestHeader(unittest.TestCase):
    def test_header_is_16_bytes(self):
        self.assertEqual(P.HEADER_SIZE, 16)

    def test_exact_hello_bytes(self):
        # catches any accidental change to the header layout
        pkt = P.build_hello(client_id=1, seq_num=1, timestamp=0)
        self.assertEqual(pkt, bytes.fromhex("cd 10 01 00 00000001 0000000000000000"))

    def test_version_and_type_share_one_byte(self):
        pkt = P.build_execute_at(1, 0, 1, 0, 0)
        self.assertEqual(pkt[1] >> 4, P.VERSION)
        self.assertEqual(pkt[1] & 0x0F, MsgType.EXECUTE_AT)

    def test_64bit_timestamp_round_trip(self):
        big = 2**63 + 12345                       # needs all 64 bits
        _, msg = P.parse_packet(P.build_sync_req(2, 7, big))
        self.assertEqual(msg.ts, big)

    def test_now_us_is_monotonic(self):
        a = P.now_us()
        b = P.now_us()
        self.assertGreaterEqual(b, a)


class TestRoundTrips(unittest.TestCase):
    """Every message type: build -> parse gives back the same values."""

    def check(self, pkt, expected_type, expected_size, **fields):
        self.assertEqual(len(pkt), expected_size)
        msg_type, msg = P.parse_packet(pkt)
        self.assertEqual(msg_type, expected_type)
        for name, value in fields.items():
            self.assertEqual(getattr(msg, name), value, name)

    def test_hello(self):
        self.check(P.build_hello(3, 5, 111), MsgType.HELLO, 16, client_id=3, seq=5, ts=111)

    def test_hello_ack(self):
        self.check(P.build_hello_ack(6, 222), MsgType.HELLO_ACK, 16, seq=6, ts=222)

    def test_sync_req(self):
        self.check(P.build_sync_req(4, 9, 333), MsgType.SYNC_REQ, 16, client_id=4, seq=9, ts=333)

    def test_sync_resp(self):
        self.check(P.build_sync_resp(10, 444, 1, 2, 3), MsgType.SYNC_RESP, 16 + 24,
                   seq=10, ts=444, t1=1, t2=2, t3=3)

    def test_execute_at(self):
        self.check(P.build_execute_at(11, 555, 7, 999_999, 0xBEEF), MsgType.EXECUTE_AT, 16 + 14,
                   seq=11, cmd_id=7, target_time_us=999_999, action_cmd=0xBEEF)

    def test_action_confirm_negative_offset(self):
        self.check(P.build_action_confirm(2, 12, 666, 7, 1000, 1001, -137_000, P.STATUS_EXECUTED),
                   MsgType.ACTION_CONFIRM, 16 + 29, client_id=2, cmd_id=7, exec_time_us=1000,
                   true_exec_us=1001, offset_us=-137_000, status=P.STATUS_EXECUTED)

    def test_error(self):
        self.check(P.build_error(0, 13, 777, P.ERR_UNKNOWN_CLIENT), MsgType.ERROR, 16 + 2,
                   error_code=P.ERR_UNKNOWN_CLIENT)

    def test_bye(self):
        self.check(P.build_bye(14, 888), MsgType.BYE, 16, seq=14, ts=888)

    def test_all_payloads_within_limit(self):
        for size in (P.SYNC_RESP_SIZE, P.EXECUTE_AT_SIZE, P.ACTION_CONFIRM_SIZE, P.ERROR_SIZE):
            self.assertLessEqual(size, P.MAX_PAYLOAD)


class TestMalformed(unittest.TestCase):
    """Bad input must raise ProtocolError, never crash or parse silently."""

    def assertRejected(self, data):
        with self.assertRaises(ProtocolError):
            P.parse_packet(data)

    def test_too_short(self):
        self.assertRejected(b"\xcd\x10\x01")

    def test_bad_magic(self):
        pkt = bytearray(P.build_hello(1, 1, 0))
        pkt[0] = 0xAB
        self.assertRejected(bytes(pkt))

    def test_bad_version(self):
        pkt = bytearray(P.build_hello(1, 1, 0))
        pkt[1] = (2 << 4) | MsgType.HELLO
        self.assertRejected(bytes(pkt))

    def test_unknown_type(self):
        pkt = bytearray(P.build_hello(1, 1, 0))
        pkt[1] = (P.VERSION << 4) | 0x0F
        self.assertRejected(bytes(pkt))

    def test_extra_payload_on_empty_message(self):
        self.assertRejected(P.build_hello(1, 1, 0) + b"x")

    def test_short_payload(self):
        self.assertRejected(P.build_sync_resp(1, 0, 1, 2, 3)[:-1])

    def test_oversized_payload(self):
        self.assertRejected(P.build_hello(1, 1, 0) + b"\x00" * (P.MAX_PAYLOAD + 1))

    def test_parser_rejects_wrong_type(self):
        # HELLO and BYE have identical layouts: the type check must tell them apart
        with self.assertRaises(ProtocolError):
            P.parse_hello(P.build_bye(1, 0))

    def test_garbage(self):
        self.assertRejected(struct.pack("!Q", 0xDEADBEEF) * 4)


if __name__ == "__main__":
    unittest.main()
