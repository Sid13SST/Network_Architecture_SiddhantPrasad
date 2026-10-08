"""Codec tests, including the exact byte examples printed in SPEC.md."""

import unittest

from support import h  # noqa: F401  (also puts the repo on sys.path)
from bhtp import protocol as P


class FrameHeader(unittest.TestCase):
    def test_layout_is_24_8_8_24(self):
        raw = P.pack_header(0x123456, 0xAB, 0xCD, 0x789ABC)
        self.assertEqual(raw, h("12 34 56 ab cd 78 9a bc"))
        self.assertEqual(P.unpack_header(raw), (0x123456, 0xAB, 0xCD, 0x789ABC))

    def test_limits(self):
        P.pack_header(P.MAX_LENGTH, 1, 0, P.MAX_STREAM_ID)
        with self.assertRaises(ValueError):
            P.pack_header(P.MAX_LENGTH + 1, 1, 0, 1)
        with self.assertRaises(ValueError):
            P.pack_header(0, 1, 0, P.MAX_STREAM_ID + 1)

    def test_spec_preface(self):
        self.assertEqual(P.PREFACE, h("89 42 48 54 50 0d 0a 01"))


class SpecExamples(unittest.TestCase):
    """The bytes in SPEC.md / HEXDUMP.md must be what the code produces."""

    REQUEST = h("""
        00 00 31 01 01 00 00 01  01 00 0b 2f 69 6e 64 65
        78 2e 68 74 6d 6c 01 00  0e 6c 6f 63 61 6c 68 6f
        73 74 3a 39 30 30 30 02  00 09 62 63 75 72 6c 2f
        31 2e 30 03 00 03 2a 2f  2a""")

    def test_request_example(self):
        payload = P.encode_request("GET", "/index.html", [
            ("host", "localhost:9000"), ("user-agent", "bcurl/1.0"),
            ("accept", "*/*")])
        self.assertEqual(P.build_frame(P.REQUEST, P.END_STREAM, 1, payload),
                         self.REQUEST)

    def test_request_example_decodes(self):
        req = P.decode_request(self.REQUEST[8:])
        self.assertEqual((req.method, req.path), ("GET", "/index.html"))
        self.assertEqual(P.get_field(req.fields, "host"), "localhost:9000")

    def test_spec_literal_field_example(self):
        # SPEC 6: "x-trace: 7" as a literal
        self.assertEqual(P.encode_fields([("x-trace", "7")]),
                         h("00 07 78 2d 74 72 61 63 65 00 01 37"))


class Fields(unittest.TestCase):
    def test_static_names_are_indexed(self):
        for i, name in enumerate(P.STATIC_TABLE[1:], 1):
            self.assertEqual(P.encode_fields([(name, "v")])[0], i)
        self.assertEqual(P.STATIC_LAST, 10)

    def test_roundtrip_with_literals_and_duplicates(self):
        fields = [("host", "a"), ("x-one", ""), ("x-one", "two"),
                  ("content-length", "5"), ("accept", "ü" * 300)]
        self.assertEqual(P.decode_fields(P.encode_fields(fields)), fields)

    def test_names_are_lowercased_on_send(self):
        self.assertEqual(P.decode_fields(P.encode_fields([("X-Foo", "1")])),
                         [("x-foo", "1")])

    def test_literal_form_of_static_name_is_accepted(self):
        block = h("00 04") + b"host" + h("00 01") + b"x"
        self.assertEqual(P.decode_fields(block), [("host", "x")])

    def test_reserved_index_is_skipped_not_fatal(self):
        block = (h("0b 00 03") + b"abc" + h("ff 00 00")
                 + h("01 00 01") + b"h")
        self.assertEqual(P.decode_fields(block), [("host", "h")])
        self.assertEqual([f.name for f in P.walk_fields(block)],
                         [None, None, "host"])

    def test_malformed_blocks(self):
        bad = {
            "truncated index": h("00"),
            "zero name length": h("00 00 00 00"),
            "name past end": h("00 05 61 62"),
            "upper-case name": h("00 01 41 00 00"),
            "space in name": h("00 02 61 20 00 00"),
            "value length past end": h("01 00 05 61"),
            "missing value length": h("01 00"),
            "CR in value": h("01 00 02 61 0d"),
            "LF in value": h("01 00 01 0a"),
            "NUL in value": h("01 00 01 00"),
        }
        for what, block in bad.items():
            with self.subTest(what):
                with self.assertRaises(P.Malformed):
                    P.decode_fields(block)

    def test_sender_refuses_injection(self):
        with self.assertRaises(P.Malformed):
            P.encode_fields([("x", "a\r\nevil: 1")])
        with self.assertRaises(P.Malformed):
            P.encode_fields([("Bad Name", "1")])


class Payloads(unittest.TestCase):
    def test_request_errors(self):
        bad = {
            "empty": b"",
            "two bytes": h("01 00"),
            "path overruns": h("01 00 09") + b"/x",
            "no slash": h("01 00 01") + b"x",
            "bad utf-8": h("01 00 02 2f ff"),
            "NUL in path": h("01 00 02 2f 00"),
        }
        for what, payload in bad.items():
            with self.subTest(what):
                with self.assertRaises(P.Malformed):
                    P.decode_request(payload)

    def test_query_split_and_unknown_method(self):
        req = P.decode_request(h("63 00 06") + b"/a?b=c")
        self.assertEqual((req.method, req.path, req.query), (None, "/a", "b=c"))
        self.assertEqual(req.method_code, 0x63)

    def test_response_roundtrip_and_range(self):
        resp = P.decode_response(P.encode_response(404, [("server", "s")]))
        self.assertEqual(resp, (404, [("server", "s")]))
        for payload in (b"", b"\x00", h("00 63"), h("02 58")):
            with self.assertRaises(P.Malformed):
                P.decode_response(payload)

    def test_goaway(self):
        self.assertEqual(P.encode_goaway(P.NO_ERROR, "done"), h("00 00") + b"done")
        self.assertEqual(P.decode_goaway(h("00 04") + b"v"),
                         (P.VERSION_UNSUPPORTED, "v"))
        self.assertEqual(P.decode_goaway(b"\x00")[0], P.PROTOCOL_ERROR)


if __name__ == "__main__":
    unittest.main()
