"""bcurl tests, run as a real subprocess.

Half of them talk to bserve; the other half talk to FakeServer, a separate
~40-line server written straight from SPEC.md that also sends the weird but
legal things bserve never does (unknown frame types, reserved header
indexes, odd flags). "A client that only works against your own server is
an implementation, not a protocol."
"""

import os
import socket
import subprocess
import sys
import threading
import unittest

from support import PREFACE, ROOT, LiveServer, frame, h, read_frame, recv_exact

BCURL = os.path.join(ROOT, "bcurl")


def bcurl(*args, timeout=20):
    p = subprocess.run([sys.executable, BCURL] + list(args),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=timeout)
    return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")


def resp(status, extra=b""):
    return status.to_bytes(2, "big") + extra


class FakeServer:
    """Accepts connections; for each REQUEST calls script(sid, path) which
    returns raw bytes to send back. Records what it saw."""

    def __init__(self, script, preface=PREFACE):
        self.script, self.preface = script, preface
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.accepts, self.frames = 0, []
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.accepts += 1
            try:
                with conn:
                    assert recv_exact(conn, 8) == PREFACE
                    conn.sendall(self.preface)
                    while True:
                        ftype, flags, sid, payload = read_frame(conn)
                        self.frames.append((ftype, flags, sid, payload))
                        if ftype == 0x01:
                            plen = int.from_bytes(payload[1:3], "big")
                            path = payload[3:3 + plen].decode()
                            conn.sendall(self.script(sid, path))
                        elif ftype == 0x04:
                            break
            except (EOFError, OSError, AssertionError):
                pass

    def url(self, path="/"):
        return "127.0.0.1:%d%s" % (self.port, path)

    def close(self):
        self.sock.close()


class AgainstBserve(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = LiveServer()
        cls.srv.write("index.html", "<h1>hi</h1>\n")
        cls.blob = os.urandom(70000)
        cls.srv.write("blob.bin", cls.blob)
        cls.base = "127.0.0.1:%d" % cls.srv.port

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def test_body_to_stdout_exit_0(self):
        code, out, _ = bcurl(self.base + "/blob.bin")
        self.assertEqual((code, out), (0, self.blob))

    def test_404_exits_4_body_still_written(self):
        code, out, err = bcurl(self.base + "/nope")
        self.assertEqual(code, 4)
        self.assertIn(b"404 Not Found", out)
        self.assertIn("404", err)

    def test_many_urls_one_connection(self):
        before = self.srv.accepts
        code, out, _ = bcurl(self.base + "/index.html", "/index.html",
                             "bhtp://" + self.base + "/index.html")
        self.assertEqual((code, out), (0, b"<h1>hi</h1>\n" * 3))
        self.assertEqual(self.srv.accepts - before, 1)

    def test_mixed_statuses_worst_wins(self):
        code, _, _ = bcurl(self.base + "/index.html", "/nope", "/index.html")
        self.assertEqual(code, 4)

    def test_verbose_hexdumps_every_frame(self):
        code, out, err = bcurl("-v", self.base + "/index.html")
        self.assertEqual(code, 0)
        self.assertEqual(out, b"<h1>hi</h1>\n")            # stdout stays clean
        for needle in ("> PREFACE", "< PREFACE", "> REQUEST stream=1",
                       "< RESPONSE stream=1", "< DATA stream=1 flags=END_STREAM",
                       "> GOAWAY stream=0", "0000  89 42 48 54 50 0d 0a 01"):
            self.assertIn(needle, err)

    def test_head_and_include(self):
        code, out, _ = bcurl("-I", self.base + "/index.html")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith(b"BHTP/1 200 OK\r\n"))
        self.assertIn(b"content-length: 12\r\n", out)
        self.assertTrue(out.endswith(b"\r\n\r\n"))

    def test_grease_is_harmless(self):
        code, out, _ = bcurl("--grease", self.base + "/index.html", "/index.html")
        self.assertEqual((code, out), (0, b"<h1>hi</h1>\n" * 2))

    def test_method_and_custom_header(self):
        code, _, _ = bcurl("-X", "DELETE", self.base + "/index.html")
        self.assertEqual(code, 4)
        code, out, _ = bcurl("-H", "X-Anything: yes", self.base + "/index.html")
        self.assertEqual((code, out), (0, b"<h1>hi</h1>\n"))

    def test_usage_errors_exit_2(self):
        self.assertEqual(bcurl(self.base + "/a", "127.0.0.2:1/b")[0], 2)
        self.assertEqual(bcurl("/no-host")[0], 2)
        self.assertEqual(bcurl("-X", "BREW", self.base + "/")[0], 2)
        self.assertEqual(bcurl("http://" + self.base + "/")[0], 2)
        self.assertEqual(bcurl("-H", "nocolon", self.base + "/")[0], 2)


class AgainstFakeServer(unittest.TestCase):
    def tearDown(self):
        self.fake.close()

    def test_skips_everything_unknown(self):
        def script(sid, path):
            return (frame(0x7E, 0xFF, 0, b"future")             # unknown type
                    + frame(0xF3, 0x00, sid, b"")               # GREASE
                    + frame(0x02, 0xF0, sid, resp(200,          # odd flags
                            h("fe 00 02 7a 7a")                 # reserved index
                            + h("00 06") + b"x-test" + h("00 01 31")))
                    + frame(0x03, 0x00, sid, b"hello ")
                    + frame(0x09, 0x00, sid, b"\x00" * 100)     # unknown, mid-body
                    + frame(0x03, 0x00, sid, b"")               # empty DATA
                    + frame(0x03, 0x01, sid, b"world"))
        self.fake = FakeServer(script)
        code, out, err = bcurl(self.fake.url("/x"))
        self.assertEqual((code, out), (0, b"hello world"), err)

    def test_5xx_exits_5(self):
        self.fake = FakeServer(lambda sid, p: frame(0x02, 0x01, sid, resp(503)))
        self.assertEqual(bcurl(self.fake.url())[0], 5)
        self.assertEqual(bcurl(self.fake.url(), "/")[0], 5)

    def test_request_bytes_on_the_wire(self):
        self.fake = FakeServer(lambda sid, p: frame(0x02, 0x01, sid, resp(204)))
        code, _, _ = bcurl(self.fake.url("/a%20b?q=1"), "/c")
        self.assertEqual(code, 0)
        reqs = [f for f in self.fake.frames if f[0] == 0x01]
        self.assertEqual([(f[1], f[2]) for f in reqs], [(1, 1), (1, 2)])
        self.assertTrue(reqs[0][3].startswith(h("01 00 08") + b"/a b?q=1"))
        self.assertEqual(self.fake.frames[-1][0], 0x04)        # polite GOAWAY
        self.assertEqual(self.fake.accepts, 1)

    def test_goaway_mid_conversation_exits_3(self):
        self.fake = FakeServer(lambda sid, p: frame(
            0x04, 0, 0, h("00 03") + b"oops"))
        code, _, err = bcurl(self.fake.url())
        self.assertEqual(code, 3)
        self.assertIn("INTERNAL_ERROR", err)

    def test_content_length_mismatch_exits_3(self):
        self.fake = FakeServer(lambda sid, p: frame(
            0x02, 0, sid, resp(200, h("05 00 02 31 30"))) + frame(0x03, 1, sid, b"short"))
        self.assertEqual(bcurl(self.fake.url())[0], 3)

    def test_non_bhtp_server_exits_3(self):
        self.fake = FakeServer(lambda sid, p: b"", preface=b"HTTP/1.1")
        self.assertEqual(bcurl(self.fake.url())[0], 3)

    def test_connection_refused_exits_3(self):
        self.fake = FakeServer(lambda sid, p: b"")
        port = self.fake.port
        self.fake.close()
        self.assertEqual(bcurl("127.0.0.1:%d/" % port, "--timeout", "2")[0], 3)


if __name__ == "__main__":
    unittest.main()
