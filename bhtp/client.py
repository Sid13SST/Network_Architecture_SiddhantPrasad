"""bcurl - a BHTP/1 client.

    ./bcurl -v localhost:9000/index.html

Builds a binary REQUEST frame, reads the RESPONSE and DATA frames, writes
the body to stdout. Several URLs are fetched one after another over ONE
connection; bcurl never opens a second one.

Exit status: 0 success, 2 usage, 3 connection/protocol error,
             4 a 4xx response, 5 a 5xx response.
"""

import argparse
import os
import random
import socket
import sys
from urllib.parse import unquote, urlsplit

from . import __version__
from . import protocol as P
from .hexdump import describe, hexdump
from .wire import ConnectionClosed, FrameIO, ProtocolError

USER_AGENT = "bcurl/%s" % __version__
DEFAULT_PORT = 9000
EXIT_OK, EXIT_USAGE, EXIT_PROTOCOL, EXIT_4XX, EXIT_5XX = 0, 2, 3, 4, 5


class UsageError(Exception):
    pass


def parse_target(url, previous=None):
    """'host:port/path', 'bhtp://host:port/path', or '/path' (reuse host)."""
    if url.startswith("/"):
        if previous is None:
            raise UsageError("%s: first URL needs a host" % url)
        host, port, authority, _ = previous
        u = urlsplit("bhtp://%s%s" % (authority, url))
    else:
        if "://" not in url:
            url = "bhtp://" + url
        u = urlsplit(url)
        if u.scheme != "bhtp":
            raise UsageError("%s: scheme must be bhtp://" % url)
        try:
            host, port = u.hostname, u.port or DEFAULT_PORT
        except ValueError:
            raise UsageError("%s: bad port" % url)
        if not host:
            raise UsageError("%s: no host" % url)
        authority = u.netloc
    # BHTP paths are length-prefixed, so they travel decoded (SPEC 5).
    path = unquote(u.path or "/") + ("?" + u.query if u.query else "")
    return host, port, authority, path


def parse_header(text):
    name, sep, value = text.partition(":")
    if not sep or not name.strip():
        raise UsageError("-H %r: expected 'name: value'" % text)
    return name.strip().lower(), value.strip()


class Client:
    def __init__(self, args):
        self.args = args
        self.out = sys.stdout.buffer
        self.io = None

    # -- verbose output --------------------------------------------------
    def info(self, msg):
        if self.args.verbose:
            sys.stderr.write("* %s\n" % msg)
            sys.stderr.flush()

    def trace(self, direction, raw, hdr, payload):
        if hdr is None:
            title = "PREFACE  %d bytes" % len(raw)
            body = ["magic %r, version %d" % (raw[:7], raw[7])]
        else:
            title = "%s stream=%d flags=%s length=%d" % (
                P.frame_name(hdr.type), hdr.stream_id,
                P.flag_names(hdr.flags), hdr.length)
            body = describe(hdr, payload)
        limit = (self.args.dump_limit
                 if hdr is not None and hdr.type == P.DATA else None)
        lines = (["%s %s" % (direction, title)]
                 + hexdump(raw, "%s   " % direction, limit)
                 + ["%s     %s" % (direction, b) for b in body])
        sys.stderr.write("\n".join(lines) + "\n")
        sys.stderr.flush()

    # -- the conversation ------------------------------------------------
    def connect(self, host, port):
        self.info("connecting to %s port %d" % (host, port))
        sock = socket.create_connection((host, port), timeout=self.args.timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.info("connected to %s port %d" % sock.getpeername()[:2])
        self.io = FrameIO(sock, self.trace if self.args.verbose else None)
        self.io.send_preface()
        raw = self.io.recv_preface()
        if raw[:7] != P.PREFACE_MAGIC:
            raise ProtocolError(P.PROTOCOL_ERROR,
                                "server did not answer with a BHTP preface")
        if raw[7] != P.VERSION:
            raise ProtocolError(P.VERSION_UNSUPPORTED,
                                "server speaks BHTP/%d" % raw[7])

    def fetch(self, sid, method, authority, path, extra):
        fields = [("host", authority), ("user-agent", USER_AGENT),
                  ("accept", "*/*")]
        names = {n for n, _ in extra}
        fields = [f for f in fields if f[0] not in names] + extra
        if self.args.grease:
            self.io.send_frame(random.randint(P.GREASE_FIRST, 0xFF),
                               random.randint(0, 255), sid,
                               os.urandom(random.randint(0, 16)))
        try:
            payload = P.encode_request(method, path, fields)
        except (ValueError, P.Malformed) as e:
            raise UsageError(str(e))
        self.io.send_frame(P.REQUEST, P.END_STREAM, sid, payload)
        return self.read_response(sid, method)

    def read_response(self, sid, method):
        resp, received = None, 0
        while True:
            try:
                hdr = self.io.read_header()
            except ConnectionClosed:
                raise ProtocolError(P.PROTOCOL_ERROR,
                                    "server closed the connection mid-response")
            if hdr.type == P.GOAWAY:
                code, reason = P.decode_goaway(self.io.read_payload(hdr))
                raise ProtocolError(code, "server sent GOAWAY %s: %s" % (
                    P.ERROR_NAMES.get(code, code), reason))
            if hdr.stream_id != sid or hdr.type not in (P.RESPONSE, P.DATA):
                self.io.skip_payload(hdr)   # unknown frame: skip cleanly
                continue
            if hdr.type == P.RESPONSE:
                if resp is not None:
                    raise ProtocolError(P.PROTOCOL_ERROR,
                                        "second RESPONSE on stream %d" % sid)
                try:
                    resp = P.decode_response(self.io.read_payload(hdr))
                except P.Malformed as e:
                    raise ProtocolError(P.PROTOCOL_ERROR, "bad RESPONSE: %s" % e)
                if self.args.include:
                    self.write_head(resp)
            else:
                if resp is None:
                    raise ProtocolError(P.PROTOCOL_ERROR,
                                        "DATA before RESPONSE on stream %d" % sid)
                body = self.io.read_payload(hdr)
                received += len(body)
                self.out.write(body)
            if hdr.flags & P.END_STREAM:
                break
        self.out.flush()
        declared = P.get_field(resp.fields, "content-length")
        if (declared is not None and method != "HEAD"
                and resp.status not in (204, 304)
                and declared.isdigit() and int(declared) != received):
            raise ProtocolError(P.PROTOCOL_ERROR,
                                "content-length %s but %d body bytes arrived"
                                % (declared, received))
        return resp

    def write_head(self, resp):
        lines = ["BHTP/%d %d %s" % (P.VERSION, resp.status,
                                    P.REASONS.get(resp.status, ""))]
        lines += ["%s: %s" % kv for kv in resp.fields]
        self.out.write(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8"))

    def close(self):
        if self.io is None:
            return
        try:
            self.io.send_frame(P.GOAWAY, 0, 0, P.encode_goaway(P.NO_ERROR, "done"))
            self.io.sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        self.io.sock.close()


def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="bcurl", description="Fetch URLs over BHTP/1, all on one "
        "connection. Body goes to stdout; -v trace goes to stderr.")
    ap.add_argument("urls", nargs="+", metavar="URL",
                    help="host[:port]/path, bhtp://host[:port]/path, or "
                         "/path to reuse the previous host")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="hexdump every frame sent and received")
    ap.add_argument("-I", "--head", action="store_true",
                    help="send HEAD and print the response head")
    ap.add_argument("-i", "--include", action="store_true",
                    help="print the response head before the body")
    ap.add_argument("-X", "--request", metavar="METHOD",
                    help="method: " + ", ".join(P.METHOD_CODES))
    ap.add_argument("-H", "--header", action="append", default=[],
                    metavar="'name: value'", help="extra request header")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="connect/read timeout in seconds (default 10)")
    ap.add_argument("--dump-limit", type=int, default=None, metavar="N",
                    help="with -v, show only the first N bytes of DATA frames")
    ap.add_argument("--grease", action="store_true",
                    help="send a random unknown frame before every request")
    ap.add_argument("--version", action="version",
                    version="bcurl %s (BHTP/%d)" % (__version__, P.VERSION))
    args = ap.parse_args(argv)
    args.include = args.include or args.head
    return args


def main(argv=None):
    if hasattr(sys.stderr, "reconfigure"):  # never die on a console codec
        sys.stderr.reconfigure(errors="backslashreplace")
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        method = "HEAD" if args.head else (args.request or "GET").upper()
        if method not in P.METHOD_CODES:
            raise UsageError("unknown method %s" % method)
        extra = [parse_header(h) for h in args.header]
        targets, prev = [], None
        for url in args.urls:
            prev = parse_target(url, prev)
            if targets and prev[:2] != targets[0][:2]:
                raise UsageError("%s: all URLs must share one host:port - "
                                 "bcurl never opens a second connection" % url)
            targets.append(prev)
    except UsageError as e:
        sys.stderr.write("bcurl: %s\n" % e)
        return EXIT_USAGE

    client = Client(args)
    worst = EXIT_OK
    try:
        client.connect(*targets[0][:2])
        for sid, (_, _, authority, path) in enumerate(targets, start=1):
            resp = client.fetch(sid, method, authority, path, extra)
            if resp.status >= 400:
                sys.stderr.write("bcurl: %s -> %d %s\n" % (
                    path, resp.status, P.REASONS.get(resp.status, "")))
            if resp.status >= 500:
                worst = EXIT_5XX
            elif resp.status >= 400 and worst != EXIT_5XX:
                worst = EXIT_4XX
        client.info("closing connection (sent %d request%s on it)"
                    % (len(targets), "" if len(targets) == 1 else "s"))
    except UsageError as e:
        sys.stderr.write("bcurl: %s\n" % e)
        return EXIT_USAGE
    except (ProtocolError, ConnectionClosed) as e:
        sys.stderr.write("bcurl: protocol error: %s\n" % (e or "connection closed"))
        return EXIT_PROTOCOL
    except socket.timeout:
        sys.stderr.write("bcurl: timed out after %gs\n" % args.timeout)
        return EXIT_PROTOCOL
    except OSError as e:
        sys.stderr.write("bcurl: %s\n" % e)
        return EXIT_PROTOCOL
    finally:
        client.close()
    return worst
