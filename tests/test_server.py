"""Conformance tests for bserve.

Every request here is assembled by hand from SPEC.md (see support.frame /
support.get) and every reply is decoded by hand, so these tests check the
server against the spec rather than against its own codec.
"""

import os
import random
import socket
import time
import unittest

from support import (PREFACE, LiveServer, frame, get, h, read_frame,
                     read_message, recv_exact)

END = 0x01


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.srv = LiveServer()
        self.index = self.srv.write("index.html", "<h1>hi</h1>\n")
        self.srv.write("docs/index.html", "docs")
        self.srv.write("empty.txt", b"")

    def tearDown(self):
        self.srv.close()

    def request(self, sock, sid, payload, flags=END):
        sock.sendall(frame(0x01, flags, sid, payload))
        return read_message(sock)

    # -- the happy path ----------------------------------------------------
    def test_get_returns_file_and_headers(self):
        with self.srv.connect() as s:
            sid, status, fields, body, frames = self.request(s, 1, get("/index.html"))
        self.assertEqual((sid, status, body), (1, 200, b"<h1>hi</h1>\n"))
        self.assertEqual(fields["content-type"], "text/html; charset=utf-8")
        self.assertEqual(fields["content-length"], "12")
        for name in ("server", "date", "last-modified", "etag"):
            self.assertIn(name, fields)
        self.assertEqual([f[0] for f in frames], [0x02, 0x03])

    def test_directory_serves_index_and_query_is_ignored(self):
        with self.srv.connect() as s:
            self.assertEqual(self.request(s, 1, get("/docs/"))[3], b"docs")
            self.assertEqual(self.request(s, 2, get("/docs"))[3], b"docs")
            self.assertEqual(self.request(s, 3, get("/?x=1"))[3], b"<h1>hi</h1>\n")

    def test_keep_alive_many_requests_one_connection(self):
        with self.srv.connect() as s:
            for sid in range(1, 51):
                self.assertEqual(self.request(s, sid, get("/index.html"))[1], 200)
        self.assertEqual(self.srv.accepts, 1)

    def test_pipelined_requests_answered_in_order(self):
        with self.srv.connect() as s:
            s.sendall(b"".join(frame(1, END, sid, get(p)) for sid, p in
                               [(1, "/index.html"), (2, "/nope"), (3, "/docs/")]))
            got = [read_message(s)[:2] for _ in range(3)]
        self.assertEqual(got, [(1, 200), (2, 404), (3, 200)])

    def test_large_file_is_chunked_and_byte_exact(self):
        blob = os.urandom(200 * 1024 + 7)
        self.srv.write("big.bin", blob)
        with self.srv.connect() as s:
            _, status, fields, body, frames = self.request(s, 1, get("/big.bin"))
        self.assertEqual((status, body), (200, blob))
        self.assertEqual(fields["content-length"], str(len(blob)))
        data = [f for f in frames if f[0] == 0x03]
        self.assertTrue(all(f[3] <= 16384 for f in data))
        self.assertEqual([f[1] & END for f in data], [0] * (len(data) - 1) + [1])

    def test_unicode_path(self):
        self.srv.write("grüße.txt", "ok")
        with self.srv.connect() as s:
            self.assertEqual(self.request(s, 1, get("/grüße.txt"))[3], b"ok")

    def test_head_and_empty_file(self):
        with self.srv.connect() as s:
            _, status, fields, body, frames = self.request(
                s, 1, b"\x02" + get("/index.html")[1:])
            self.assertEqual((status, body, fields["content-length"]), (200, b"", "12"))
            self.assertEqual(frames, [(0x02, END, 1, frames[0][3])])
            _, status, fields, body, _ = self.request(s, 2, get("/empty.txt"))
            self.assertEqual((status, body, fields["content-length"]), (200, b"", "0"))

    def test_conditional_get_304(self):
        with self.srv.connect() as s:
            etag = self.request(s, 1, get("/index.html"))[2]["etag"]
            inm = h("00 0d") + b"if-none-match" + len(etag).to_bytes(2, "big") + etag.encode()
            _, status, fields, body, _ = self.request(s, 2, get("/index.html", inm))
        self.assertEqual((status, body, fields["etag"]), (304, b"", etag))

    # -- errors that keep the connection open -----------------------------
    def assertStatusThenStillAlive(self, payload, status, sid=1, ftype=0x01):
        with self.srv.connect() as s:
            s.sendall(frame(ftype, END, sid, payload))
            got_sid, got, fields, body, _ = read_message(s)
            self.assertEqual((got_sid, got), (sid, status), body)
            # connection survives: a good request on the next stream works
            self.assertEqual(self.request(s, sid + 1, get("/index.html"))[1], 200)
        return fields, body

    def test_404(self):
        _, body = self.assertStatusThenStillAlive(get("/missing.html"), 404)
        self.assertIn(b"not found", body)

    def test_400_malformed_frames(self):
        cases = {
            "empty payload": b"",
            "path length overruns": h("01 00 ff") + b"/x",
            "path without slash": h("01 00 05") + b"index",
            "invalid utf-8": h("01 00 02 2f c3"),
            "truncated field": get("/index.html", h("01 00 09") + b"abc"),
            "upper-case literal name": get("/", h("00 01 58 00 00")),
            "CRLF in value": get("/", h("01 00 03 61 0d 0a")),
            "dot-dot traversal": get("/../../etc/passwd"),
            "backslash": get("/..\\secret"),
        }
        for what, payload in cases.items():
            with self.subTest(what):
                _, body = self.assertStatusThenStillAlive(payload, 400)
                self.assertTrue(body.startswith(b"400 Bad Request: "), body)

    def test_400_on_bad_stream_ids(self):
        self.assertStatusThenStillAlive(get("/"), 400, sid=0)
        with self.srv.connect() as s:
            self.assertEqual(self.request(s, 5, get("/"))[1], 200)
            self.assertEqual(self.request(s, 5, get("/"))[1], 400)   # reused
            self.assertEqual(self.request(s, 3, get("/"))[1], 400)   # backwards
            self.assertEqual(self.request(s, 6, get("/"))[1], 200)

    def test_400_response_frame_from_client(self):
        self.assertStatusThenStillAlive(h("00 c8"), 400, ftype=0x02)

    def test_405_501_and_options(self):
        fields, _ = self.assertStatusThenStillAlive(b"\x03" + get("/")[1:], 405)
        self.assertEqual(fields["allow"], "GET, HEAD, OPTIONS")
        self.assertStatusThenStillAlive(b"\x63" + get("/")[1:], 501)
        fields, body = self.assertStatusThenStillAlive(b"\x06" + get("/")[1:], 204)
        self.assertEqual((body, fields["allow"]), (b"", "GET, HEAD, OPTIONS"))

    def test_431_oversized_request(self):
        huge = get("/", h("00 01 78") + (20000).to_bytes(2, "big") + b"a" * 20000)
        self.assertStatusThenStillAlive(huge, 431)

    def test_request_body_is_drained(self):
        with self.srv.connect() as s:
            s.sendall(frame(0x01, 0, 1, get("/index.html"))      # body follows
                      + frame(0x03, 0, 1, b"x" * 1000)
                      + frame(0x03, END, 1, b"y"))
            self.assertEqual(read_message(s)[1], 200)
            self.assertEqual(self.request(s, 2, get("/index.html"))[1], 200)

    @unittest.skipUnless(hasattr(os, "symlink"), "no symlinks")
    def test_symlink_out_of_root_is_404(self):
        secret = os.path.join(self.srv.tmp, "secret.txt")
        with open(secret, "w") as f:
            f.write("nope")
        try:
            os.symlink(secret, os.path.join(self.srv.root, "link.txt"))
        except OSError:
            self.skipTest("cannot create symlinks here")
        self.assertStatusThenStillAlive(get("/link.txt"), 404)

    # -- THE rule: unknown things are skipped cleanly ----------------------
    def test_unknown_frame_types_are_skipped(self):
        with self.srv.connect() as s:
            for ftype in (0x00, 0x05, 0x7F, 0xEF, 0xF0, 0xFF):
                s.sendall(frame(ftype, 0xFF, 0, os.urandom(37)))
                s.sendall(frame(ftype, 0x00, 9, b""))
            self.assertEqual(self.request(s, 1, get("/index.html"))[1], 200)

    def test_huge_unknown_frame_is_skipped(self):
        with self.srv.connect() as s:
            s.sendall(frame(0x42, 0, 1, b"\xAA" * (3 * 1024 * 1024)))
            self.assertEqual(self.request(s, 1, get("/index.html"))[1], 200)

    def test_unknown_flags_ignored(self):
        with self.srv.connect() as s:
            self.assertEqual(self.request(s, 1, get("/"), flags=0xFF)[1], 200)

    def test_reserved_header_index_skipped(self):
        extra = h("0b 00 03 61 62 63") + h("fe 00 00")
        self.assertStatusThenStillAlive(get("/index.html", extra), 200)

    def test_stray_data_frames_skipped(self):
        with self.srv.connect() as s:
            s.sendall(frame(0x03, END, 77, b"stray"))
            self.assertEqual(self.request(s, 1, get("/"))[1], 200)

    # -- connection-level behaviour ----------------------------------------
    def goaway(self, sock):
        ftype, _, sid, payload = read_frame(sock)
        self.assertEqual((ftype, sid), (0x04, 0))
        return int.from_bytes(payload[:2], "big"), payload[2:]

    def test_bad_preface_goaway(self):
        with self.srv.connect(preface=False) as s:
            s.sendall(b"\x00" * 8)
            self.assertEqual(recv_exact(s, 8), PREFACE)
            self.assertEqual(self.goaway(s)[0], 0x0001)
            self.assertEqual(s.recv(1), b"")

    def test_future_version_goaway(self):
        with self.srv.connect(preface=False) as s:
            s.sendall(PREFACE[:7] + b"\x02")
            self.assertEqual(recv_exact(s, 8), PREFACE)
            self.assertEqual(self.goaway(s)[0], 0x0004)

    def test_text_http_client_gets_text_400(self):
        with self.srv.connect(preface=False) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            reply = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                reply += chunk
        self.assertTrue(reply.startswith(b"HTTP/1.1 400 Bad Request\r\n"))
        self.assertIn(b"BHTP/1", reply)

    def test_client_goaway_closes(self):
        with self.srv.connect() as s:
            s.sendall(frame(0x04, 0, 0, h("00 00") + b"bye"))
            self.assertEqual(s.recv(1), b"")

    def test_idle_timeout_goaway(self):
        self.srv.close()
        self.srv = LiveServer(idle_timeout=0.3)
        with self.srv.connect() as s:
            code, reason = self.goaway(s)
        self.assertEqual(code, 0x0000)
        self.assertIn(b"idle", reason)

    def test_truncated_frame_does_not_hurt_server(self):
        with self.srv.connect() as s:
            s.sendall(frame(0x01, END, 1, get("/index.html"))[:-3])
        with self.srv.connect() as s:
            self.assertEqual(self.request(s, 1, get("/index.html"))[1], 200)

    def test_concurrent_connections(self):
        socks = [self.srv.connect() for _ in range(10)]
        try:
            for i, s in enumerate(socks):
                s.sendall(frame(0x01, END, 1, get("/index.html")))
            for s in socks:
                self.assertEqual(read_message(s)[1], 200)
        finally:
            for s in socks:
                s.close()

    def test_fuzz_server_survives_garbage(self):
        rng = random.Random(1234)
        for _ in range(150):
            with self.srv.connect() as s:
                s.settimeout(0.5)
                blob = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 300)))
                if rng.random() < 0.5:    # plausible header, random payload
                    blob = frame(rng.choice([1, 2, 3, 4, 0x99]), rng.getrandbits(8),
                                 rng.randint(0, 5), blob)
                try:
                    s.sendall(blob)
                    s.shutdown(socket.SHUT_WR)
                    while s.recv(65536):
                        pass
                except OSError:
                    pass
        time.sleep(0.1)
        with self.srv.connect() as s:
            self.assertEqual(self.request(s, 1, get("/index.html"))[1], 200)


if __name__ == "__main__":
    unittest.main()
