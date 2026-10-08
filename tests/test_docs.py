"""The bytes printed in SPEC.md and HEXDUMP.md must be what the code emits.

If someone edits the protocol and forgets the documents (or vice versa),
these tests fail. "If you cannot annotate your own bytes, the spec is not
finished" - and if the annotation is wrong, the build is not green.
"""

import os
import re
import unittest

from support import ROOT, h
from bhtp import protocol as P


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


def hex_tokens(line):
    """Leading run of 2-digit hex tokens on a line (stops at the comment)."""
    out = []
    for tok in line.split():
        if tok == "|":
            continue
        if not re.fullmatch(r"[0-9a-f]{2}", tok):
            break
        out.append(tok)
    return out


REQUEST_FIELDS = [("host", "localhost:9000"), ("user-agent", "bcurl/1.0"),
                  ("accept", "*/*")]


class Docs(unittest.TestCase):
    def test_spec_worked_example(self):
        text = read("SPEC.md").split("## 9.")[1]
        block = text.split("```")[1]
        raw = h(" ".join(t for line in block.splitlines()
                         for t in hex_tokens(line)))
        expected = P.build_frame(P.REQUEST, P.END_STREAM, 1, P.encode_request(
            "GET", "/index.html", REQUEST_FIELDS))
        self.assertEqual(raw, expected)
        self.assertEqual(len(raw), 57)

    def test_spec_preface_and_literal_example(self):
        spec = read("SPEC.md")
        self.assertIn("`89 42 48 54 50 0D 0A 01`", spec)
        self.assertIn("`00 07 78 2d 74 72 61 63 65 00 01 37`", spec)

    def test_hexdump_client_stream(self):
        text = read("HEXDUMP.md").split("all 78 bytes")[1]
        block = text.split("```")[1]
        raw = h(" ".join(t for line in block.splitlines()
                         for t in hex_tokens(line)))
        expected = (P.PREFACE
                    + P.build_frame(P.REQUEST, P.END_STREAM, 1, P.encode_request(
                        "GET", "/hello.txt", REQUEST_FIELDS))
                    + P.build_frame(P.GOAWAY, 0, 0,
                                    P.encode_goaway(P.NO_ERROR, "done")))
        self.assertEqual(raw, expected)

    def test_hexdump_server_frames_decode(self):
        text = read("HEXDUMP.md")
        for name, expect in (("RESPONSE", 136), ("DATA", 28)):
            block = text.split("### ")[[s.split()[1] for s in
                                        text.split("### ")[1:]].index(name) + 1]
            dump = block.split("```")[1]
            raw = h(" ".join(line[6:55] for line in dump.strip().splitlines()))
            self.assertEqual(len(raw), expect)
            hdr = P.unpack_header(raw[:8])
            self.assertEqual(hdr.length, len(raw) - 8)
            if name == "RESPONSE":
                resp = P.decode_response(raw[8:])
                self.assertEqual(resp.status, 200)
                self.assertEqual(P.get_field(resp.fields, "content-length"), "20")
            else:
                self.assertEqual(raw[8:], b"hello, binary world\n")


if __name__ == "__main__":
    unittest.main()
