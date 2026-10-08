"""Shared test helpers: a real bserve on an ephemeral port, raw sockets."""

import argparse
import os
import shutil
import socket
import sys
import tempfile
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from bhtp import server  # noqa: E402


def h(text):
    """Hex string from the spec (spaces/newlines ignored) -> bytes."""
    return bytes.fromhex("".join(text.split()))


PREFACE = h("89 42 48 54 50 0d 0a 01")


class LiveServer:
    """bserve running in a thread over a throw-away copy of a docroot."""

    def __init__(self, idle_timeout=5.0, grease=False):
        self.tmp = tempfile.mkdtemp(prefix="bhtp-test-")
        self.root = os.path.join(self.tmp, "www")
        os.mkdir(self.root)
        self.accepts = 0
        cfg = argparse.Namespace(root=os.path.realpath(self.root),
                                 verbose=False, quiet=True,
                                 idle_timeout=idle_timeout, grease=grease,
                                 dump_limit=None)
        self.listener = server.make_listener("127.0.0.1", 0)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        # count accepted connections by wrapping accept()
        real_accept = self.listener.accept

        class Counting:
            def __getattr__(_, name):
                return getattr(self.listener_raw, name)

            def accept(_):
                conn = real_accept()
                self.accepts += 1
                return conn
        self.listener_raw = self.listener
        self.thread = threading.Thread(target=server.serve,
                                       args=(cfg, Counting(), self.stop),
                                       daemon=True)
        self.thread.start()

    def write(self, rel, data):
        path = os.path.join(self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        return path

    def connect(self, preface=True):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        if preface:
            s.sendall(PREFACE)
            assert recv_exact(s, 8) == PREFACE
        return s

    def close(self):
        self.stop.set()
        self.thread.join(2)
        self.listener_raw.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("got %d of %d bytes" % (len(buf), n))
        buf += chunk
    return buf


def read_frame(sock):
    """Decode one frame by hand from SPEC 3 - deliberately not using bhtp."""
    hdr = recv_exact(sock, 8)
    length = int.from_bytes(hdr[0:3], "big")
    return (hdr[3], hdr[4], int.from_bytes(hdr[5:8], "big"),
            recv_exact(sock, length) if length else b"")


def frame(ftype, flags, sid, payload=b""):
    return (len(payload).to_bytes(3, "big") + bytes([ftype, flags])
            + sid.to_bytes(3, "big") + payload)


def get(path, extra=b""):
    """Hand-built GET REQUEST payload: method, path length, path, fields."""
    raw = path.encode("utf-8")
    return b"\x01" + len(raw).to_bytes(2, "big") + raw + extra


def read_message(sock):
    """Read RESPONSE + DATA... until END_STREAM, skipping unknown types.

    Returns (stream_id, status, fields, body, frames_seen)."""
    status, fields, body, frames, sid = None, {}, b"", [], None
    while True:
        ftype, flags, sid_, payload = read_frame(sock)
        frames.append((ftype, flags, sid_, len(payload)))
        if ftype == 0x02:
            sid = sid_
            status = int.from_bytes(payload[0:2], "big")
            fields = parse_fields(payload[2:])
        elif ftype == 0x03:
            body += payload
        elif ftype == 0x04:
            raise AssertionError("unexpected GOAWAY %r" % payload)
        else:
            continue
        if flags & 0x01:
            return sid, status, fields, body, frames


STATIC = [None, "host", "user-agent", "accept", "content-type",
          "content-length", "server", "date", "last-modified", "etag", "allow"]


def parse_fields(block):
    out, i = {}, 0
    while i < len(block):
        idx = block[i]
        i += 1
        if idx == 0:
            n = block[i]
            name = block[i + 1:i + 1 + n].decode()
            i += 1 + n
        else:
            name = STATIC[idx] if idx < len(STATIC) else None
        vlen = int.from_bytes(block[i:i + 2], "big")
        value = block[i + 2:i + 2 + vlen].decode()
        i += 2 + vlen
        if name:
            out[name] = value
    return out
