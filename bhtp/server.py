"""bserve - a BHTP/1 static file server.

    ./bserve ./www 9000

Accepts TCP connections, reads binary REQUEST frames, maps the path to a
file under the root and answers with a RESPONSE frame followed by DATA
frames. Connections stay open until the client leaves, an idle timeout
fires, or the byte stream becomes untrustworthy.
"""

import argparse
import email.utils
import os
import random
import socket
import sys
import threading

from . import __version__
from . import protocol as P
from .hexdump import describe, hexdump
from .wire import ConnectionClosed, FrameIO, ProtocolError, recv_exact

SERVER_NAME = "bserve/%s" % __version__
ALLOWED = "GET, HEAD, OPTIONS"

MIME_TYPES = {
    ".html": "text/html; charset=utf-8", ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".json": "application/json", ".txt": "text/plain; charset=utf-8",
    ".md": "text/markdown; charset=utf-8", ".xml": "application/xml",
    ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
    ".ico": "image/x-icon", ".pdf": "application/pdf",
    ".wasm": "application/wasm", ".bin": "application/octet-stream",
}

_HTTP1_STARTS = (b"GET ", b"HEAD", b"POST", b"PUT ", b"DELE", b"OPTI",
                 b"PATC", b"CONN", b"TRAC", b"PRI ")

_log_lock = threading.Lock()


def log(*lines):
    with _log_lock:
        for line in lines:
            sys.stderr.write(line + "\n")
        sys.stderr.flush()


def mime_type(path):
    return MIME_TYPES.get(os.path.splitext(path)[1].lower(),
                          "application/octet-stream")


def resolve(root, path):
    """Map a request path to a regular file under root, or return None.

    Raises Malformed for paths no honest client sends ('..' segments,
    backslashes); those are 400, everything else that is not there is 404.
    """
    segments = path.split("/")
    for seg in segments:
        if seg == "..":
            raise P.Malformed("path contains a '..' segment")
        if "\\" in seg:
            raise P.Malformed("path contains a backslash")
    rel = [s for s in segments if s not in ("", ".")]
    if os.name == "nt" and any(":" in s for s in rel):
        return None                      # drive letters / ADS streams
    full = os.path.join(root, *rel)
    if os.path.isdir(full):
        full = os.path.join(full, "index.html")
    real = os.path.realpath(full)
    # a symlink must not lead out of the root
    if os.path.commonpath([os.path.normcase(real), os.path.normcase(root)]) \
            != os.path.normcase(root):
        return None
    return real if os.path.isfile(real) else None


class Connection:
    def __init__(self, sock, addr, cfg):
        self.sock = sock
        self.peer = "%s:%d" % addr[:2]
        self.cfg = cfg
        self.io = FrameIO(sock, self._trace if cfg.verbose else None)
        self.last_stream = 0

    # -- logging ---------------------------------------------------------
    def _trace(self, direction, raw, hdr, payload):
        if hdr is None:
            title = "PREFACE  %d bytes" % len(raw)
            body = []
        else:
            title = "%s stream=%d flags=%s length=%d" % (
                P.frame_name(hdr.type), hdr.stream_id,
                P.flag_names(hdr.flags), hdr.length)
            body = describe(hdr, payload)
        pre = "[%s] %s " % (self.peer, direction)
        limit = None if hdr is None or hdr.type != P.DATA else self.cfg.dump_limit
        log(pre + title, *(hexdump(raw, pre + "  ", limit)
                           + [pre + "    " + b for b in body]))

    # -- main loop -------------------------------------------------------
    def run(self):
        self.sock.settimeout(self.cfg.idle_timeout)
        try:
            if self._handshake():
                self._serve_frames()
        except ConnectionClosed:
            pass
        except socket.timeout:
            self._goaway(P.NO_ERROR, "idle for %gs" % self.cfg.idle_timeout)
        except ProtocolError as e:
            self._goaway(e.code, str(e))
        except OSError:
            pass                         # peer vanished; nothing to tell it
        except Exception as e:           # never let one client kill us
            log("[%s] internal error: %r" % (self.peer, e))
            self._goaway(P.INTERNAL_ERROR, "internal error")
        finally:
            self._lingering_close()

    def _lingering_close(self):
        """Half-close, then drain briefly. Closing a socket that still has
        unread input makes TCP send RST, which can destroy a GOAWAY (or the
        text-HTTP 400) before the peer reads it."""
        try:
            self.sock.shutdown(socket.SHUT_WR)
            self.sock.settimeout(0.5)
            drained = 0
            while drained < 1 << 20:
                chunk = self.sock.recv(65536)
                if not chunk:
                    break
                drained += len(chunk)
        except OSError:
            pass
        finally:
            self.sock.close()

    def _handshake(self):
        raw = self.io.recv_preface()
        if raw[:7] == P.PREFACE_MAGIC:
            self.io.send_preface()
            if raw[7] != P.VERSION:
                self._goaway(P.VERSION_UNSUPPORTED,
                             "this server speaks BHTP/%d only" % P.VERSION)
                return False
            return True
        if raw.startswith(_HTTP1_STARTS):
            # A text HTTP client: tell it, in its own language, what this is.
            msg = (b"This port speaks BHTP/1 (binary HTTP). "
                   b"Use ./bcurl, see SPEC.md.\n")
            self.sock.sendall(b"HTTP/1.1 400 Bad Request\r\n"
                              b"Content-Type: text/plain\r\n"
                              b"Content-Length: %d\r\nConnection: close\r\n\r\n"
                              % len(msg) + msg)
            return False
        self.io.send_preface()
        self._goaway(P.PROTOCOL_ERROR, "bad connection preface")
        return False

    def _serve_frames(self):
        while True:
            hdr = self.io.read_header()
            if hdr.type == P.REQUEST:
                self._on_request(hdr)
            elif hdr.type == P.GOAWAY:
                self.io.read_payload(hdr)
                return                    # client said goodbye
            elif hdr.type == P.RESPONSE:
                self.io.read_payload(hdr)  # known type, wrong direction
                self._error(hdr.stream_id, 400, "RESPONSE frame sent to a server")
            else:
                # DATA for a request we already answered (or never will),
                # and every type we do not know: skip cleanly (SPEC 4).
                self.io.skip_payload(hdr)

    def _goaway(self, code, reason):
        try:
            self.io.send_frame(P.GOAWAY, 0, 0, P.encode_goaway(code, reason))
        except OSError:
            pass

    # -- requests --------------------------------------------------------
    def _on_request(self, hdr):
        sid = hdr.stream_id
        if hdr.length > P.MAX_HEAD_PAYLOAD:
            self.io.skip_payload(hdr)
            return self._error(sid, 431, "REQUEST payload of %d bytes exceeds "
                               "the %d byte limit" % (hdr.length, P.MAX_HEAD_PAYLOAD))
        payload = self.io.read_payload(hdr)
        try:
            if sid == 0:
                raise P.Malformed("stream id 0 is reserved for the connection")
            if sid <= self.last_stream:
                raise P.Malformed("stream id %d is not greater than %d"
                                  % (sid, self.last_stream))
            req = P.decode_request(payload)
        except P.Malformed as e:
            return self._error(sid, 400, str(e))
        self.last_stream = sid

        if req.method is None:
            return self._error(sid, 501, "method code 0x%02x is not defined"
                               % req.method_code)
        if req.method == "OPTIONS":
            return self._send(sid, 204, [("allow", ALLOWED)], req=req)
        if req.method not in ("GET", "HEAD"):
            return self._error(sid, 405, "%s is not allowed here" % req.method,
                               [("allow", ALLOWED)], req=req)
        try:
            path = resolve(self.cfg.root, req.path)
        except P.Malformed as e:
            return self._error(sid, 400, str(e), req=req)
        if path is None:
            return self._error(sid, 404, "%s not found" % req.path, req=req)
        self._send_file(sid, req, path)

    def _send_file(self, sid, req, path):
        try:
            f = open(path, "rb")
        except OSError:
            return self._error(sid, 404, "%s not readable" % req.path, req=req)
        with f:
            st = os.fstat(f.fileno())
            etag = '"%x-%x"' % (st.st_size, int(st.st_mtime))
            fields = [("content-type", mime_type(path)),
                      ("content-length", st.st_size),
                      ("last-modified",
                       email.utils.formatdate(st.st_mtime, usegmt=True)),
                      ("etag", etag)]
            inm = P.get_field(req.fields, "if-none-match")
            if inm is not None and (inm.strip() == "*" or etag in
                                    [t.strip() for t in inm.split(",")]):
                return self._send(sid, 304, [("etag", etag)], req=req)
            if req.method == "HEAD" or st.st_size == 0:
                return self._send(sid, 200, fields, req=req)

            self._head(sid, 200, fields, end=False)
            sent = 0
            chunk = f.read(P.DATA_CHUNK)
            while True:
                nxt = f.read(P.DATA_CHUNK)
                self.io.send_frame(P.DATA, 0 if nxt else P.END_STREAM, sid, chunk)
                sent += len(chunk)
                if not nxt:
                    break
                chunk = nxt
            if sent != st.st_size:
                # v1 has no per-stream reset: the only honest move is to
                # drop the connection (SPEC 8, and a reason for v2).
                raise ProtocolError(P.INTERNAL_ERROR, "file changed while sending")
            self._access(sid, req, 200, sent)

    # -- responses -------------------------------------------------------
    def _head(self, sid, status, fields, end):
        if self.cfg.grease:
            self.io.send_frame(random.randint(P.GREASE_FIRST, 0xFF),
                               random.randint(0, 255), sid,
                               os.urandom(random.randint(0, 16)))
        fields = [("server", SERVER_NAME),
                  ("date", email.utils.formatdate(usegmt=True))] + list(fields)
        self.io.send_frame(P.RESPONSE, P.END_STREAM if end else 0, sid,
                           P.encode_response(status, fields))

    def _send(self, sid, status, fields, body=b"", req=None):
        head_only = req is not None and req.method == "HEAD"
        if body and not head_only:
            self._head(sid, status, fields, end=False)
            for i in range(0, len(body), P.DATA_CHUNK):
                last = i + P.DATA_CHUNK >= len(body)
                self.io.send_frame(P.DATA, P.END_STREAM if last else 0, sid,
                                   body[i:i + P.DATA_CHUNK])
        else:
            self._head(sid, status, fields, end=True)
        self._access(sid, req, status, 0 if head_only else len(body))

    def _error(self, sid, status, message, fields=(), req=None):
        body = ("%d %s: %s\n" % (status, P.REASONS.get(status, ""), message)
                ).encode("utf-8")
        fields = [("content-type", "text/plain; charset=utf-8"),
                  ("content-length", len(body))] + list(fields)
        self._send(sid, status, fields, body, req)

    def _access(self, sid, req, status, nbytes):
        if self.cfg.quiet:
            return
        what = "%s %s" % (req.method, req.path) if req else "(malformed)"
        log("%s #%d %s -> %d (%d bytes)" % (self.peer, sid, what, status,
                                            nbytes))


def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="bserve", description="Serve a directory over BHTP/1.")
    ap.add_argument("root", help="directory to serve")
    ap.add_argument("port", nargs="?", type=int, default=9000,
                    help="TCP port (default 9000)")
    ap.add_argument("--host", default="0.0.0.0",
                    help="address to bind (default 0.0.0.0)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="hexdump every frame to stderr")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="no access log")
    ap.add_argument("--idle-timeout", type=float, default=30.0,
                    help="seconds of silence before GOAWAY (default 30)")
    ap.add_argument("--dump-limit", type=int, default=None, metavar="N",
                    help="with -v, show only the first N bytes of DATA frames")
    ap.add_argument("--grease", action="store_true",
                    help="send a random unknown frame before every response")
    ap.add_argument("--version", action="version",
                    version="bserve %s (BHTP/%d)" % (__version__, P.VERSION))
    return ap.parse_args(argv)


def make_listener(host, port):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    if os.name != "nt":
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(64)
    return sock


def serve(cfg, listener, stop=None):
    """Accept loop. `stop` is an optional threading.Event (used by tests)."""
    listener.settimeout(0.5)             # lets Ctrl-C work on Windows too
    while stop is None or not stop.is_set():
        try:
            sock, addr = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=Connection(sock, addr, cfg).run,
                         daemon=True).start()


def main(argv=None):
    if hasattr(sys.stderr, "reconfigure"):  # never die on a console codec
        sys.stderr.reconfigure(errors="backslashreplace")
    cfg = parse_args(sys.argv[1:] if argv is None else argv)
    if not os.path.isdir(cfg.root):
        sys.stderr.write("bserve: %s is not a directory\n" % cfg.root)
        return 2
    cfg.root = os.path.realpath(cfg.root)
    try:
        listener = make_listener(cfg.host, cfg.port)
    except OSError as e:
        sys.stderr.write("bserve: cannot listen on %s:%d: %s\n"
                         % (cfg.host, cfg.port, e))
        return 1
    log("bserve: serving %s on %s:%d (BHTP/%d)"
        % (cfg.root, cfg.host, cfg.port, P.VERSION))
    try:
        serve(cfg, listener)
    except KeyboardInterrupt:
        log("bserve: bye")
    finally:
        listener.close()
    return 0
