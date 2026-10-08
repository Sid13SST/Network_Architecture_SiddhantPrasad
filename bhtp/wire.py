"""Reading and writing BHTP frames on a socket."""

import threading

from . import protocol as P


class ConnectionClosed(Exception):
    """Peer closed the connection cleanly, on a frame boundary."""


class ProtocolError(Exception):
    """The byte stream can no longer be trusted: connection error (SPEC 8)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def recv_exact(sock, n, eof_ok=False):
    """Read exactly n bytes. EOF before the first byte is ConnectionClosed
    when eof_ok, EOF anywhere else is a ProtocolError (truncated frame)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 65536))
        if not chunk:
            if eof_ok and not buf:
                raise ConnectionClosed()
            raise ProtocolError(P.PROTOCOL_ERROR,
                                "connection closed after %d of %d bytes"
                                % (len(buf), n))
        buf += chunk
    return bytes(buf)


class FrameIO:
    """Frame-at-a-time access to a connected socket.

    `trace(direction, raw_bytes, header_or_None, payload_or_None)` is called
    for every frame (and the preface) when given; that is how -v hexdumps
    every frame without the protocol code knowing about output formats.
    """

    def __init__(self, sock, trace=None):
        self.sock = sock
        self.trace = trace
        self._send_lock = threading.Lock()

    # -- preface ---------------------------------------------------------
    def send_preface(self):
        self._send(P.PREFACE, None, None)

    def recv_preface(self):
        raw = recv_exact(self.sock, P.PREFACE_LEN, eof_ok=True)
        if self.trace:
            self.trace("<", raw, None, None)
        return raw

    # -- frames ----------------------------------------------------------
    def send_frame(self, ftype, flags, stream_id, payload=b""):
        raw = P.build_frame(ftype, flags, stream_id, payload)
        self._send(raw, P.unpack_header(raw[:8]), payload)

    def read_header(self):
        return P.unpack_header(recv_exact(self.sock, P.FRAME_HEADER_LEN,
                                          eof_ok=True))

    def read_payload(self, hdr):
        payload = recv_exact(self.sock, hdr.length) if hdr.length else b""
        if self.trace:
            self.trace("<", P.pack_header(*hdr) + payload, hdr, payload)
        return payload

    def skip_payload(self, hdr):
        """Discard a payload without ever holding more than 64 KiB of it.

        This is the mandatory unknown-frame rule (SPEC 4): read exactly
        Length bytes, throw them away, carry on.
        """
        if hdr.length <= 65536:
            return self.read_payload(hdr)
        left = hdr.length
        while left:
            left -= len(recv_exact(self.sock, min(left, 65536)))
        if self.trace:
            self.trace("<", P.pack_header(*hdr), hdr, None)
        return None

    def _send(self, raw, hdr, payload):
        with self._send_lock:
            self.sock.sendall(raw)
        if self.trace:
            self.trace(">", raw, hdr, payload)
