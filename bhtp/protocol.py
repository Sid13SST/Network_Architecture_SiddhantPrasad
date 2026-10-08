"""BHTP/1 wire format.

Everything that crosses the socket is defined in this module and nowhere
else. Section numbers in comments (e.g. "SPEC 3") refer to SPEC.md.
"""

from collections import namedtuple

# --------------------------------------------------------------------------
# SPEC 2: connection preface
# --------------------------------------------------------------------------

PREFACE_MAGIC = b"\x89BHTP\r\n"          # 7 bytes
VERSION = 1
PREFACE = PREFACE_MAGIC + bytes([VERSION])  # 8 bytes on the wire
PREFACE_LEN = len(PREFACE)

# --------------------------------------------------------------------------
# SPEC 3: frame header  |Length 24|Type 8|Flags 8|Stream ID 24|  = 8 bytes
# --------------------------------------------------------------------------

FRAME_HEADER_LEN = 8
MAX_LENGTH = (1 << 24) - 1
MAX_STREAM_ID = (1 << 24) - 1

# Frame types (SPEC 4)
REQUEST = 0x01
RESPONSE = 0x02
DATA = 0x03
GOAWAY = 0x04
GREASE_FIRST = 0xF0                      # 0xF0-0xFF: never assigned
FRAME_NAMES = {REQUEST: "REQUEST", RESPONSE: "RESPONSE",
               DATA: "DATA", GOAWAY: "GOAWAY"}

# Flags
END_STREAM = 0x01

# Limits a v1 implementation applies (SPEC 8)
DATA_CHUNK = 16 * 1024                   # senders SHOULD NOT exceed this
MAX_HEAD_PAYLOAD = 16 * 1024             # REQUEST/RESPONSE payload ceiling

# --------------------------------------------------------------------------
# SPEC 5: methods
# --------------------------------------------------------------------------

METHODS = {0x01: "GET", 0x02: "HEAD", 0x03: "POST",
           0x04: "PUT", 0x05: "DELETE", 0x06: "OPTIONS"}
METHOD_CODES = {name: code for code, name in METHODS.items()}

# --------------------------------------------------------------------------
# SPEC 6: header block, static table of the ten names we actually send
# --------------------------------------------------------------------------

LITERAL = 0x00
STATIC_TABLE = (None,            # 0x00 = literal name follows
                "host",          # 0x01  client
                "user-agent",    # 0x02  client
                "accept",        # 0x03  client
                "content-type",  # 0x04  server
                "content-length",  # 0x05  server
                "server",        # 0x06  server
                "date",          # 0x07  server
                "last-modified",  # 0x08  server
                "etag",          # 0x09  server
                "allow")         # 0x0A  server (405 / OPTIONS)
STATIC_INDEX = {name: i for i, name in enumerate(STATIC_TABLE) if name}
STATIC_LAST = len(STATIC_TABLE) - 1      # 0x0A

# tchar from RFC 9110, minus upper case (names travel lower-cased)
_TCHAR = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~")
_BAD_VALUE_BYTES = frozenset(b"\r\n\x00")

# --------------------------------------------------------------------------
# SPEC 7: GOAWAY error codes
# --------------------------------------------------------------------------

NO_ERROR = 0x0000
PROTOCOL_ERROR = 0x0001
FRAME_SIZE_ERROR = 0x0002
INTERNAL_ERROR = 0x0003
VERSION_UNSUPPORTED = 0x0004
ERROR_NAMES = {NO_ERROR: "NO_ERROR", PROTOCOL_ERROR: "PROTOCOL_ERROR",
               FRAME_SIZE_ERROR: "FRAME_SIZE_ERROR",
               INTERNAL_ERROR: "INTERNAL_ERROR",
               VERSION_UNSUPPORTED: "VERSION_UNSUPPORTED"}

REASONS = {200: "OK", 204: "No Content", 304: "Not Modified",
           400: "Bad Request", 403: "Forbidden", 404: "Not Found",
           405: "Method Not Allowed", 431: "Request Header Fields Too Large",
           500: "Internal Server Error", 501: "Not Implemented"}


class Malformed(ValueError):
    """The frame's boundaries were honoured but its contents are invalid.

    The byte stream is still in sync, so this is a *stream* error: the server
    answers 400 on that stream and keeps the connection open (SPEC 8).
    """


FrameHeader = namedtuple("FrameHeader", "length type flags stream_id")
Request = namedtuple("Request", "method_code method path query fields")
Response = namedtuple("Response", "status fields")
Field = namedtuple("Field", "offset index name value")


def frame_name(ftype):
    if ftype in FRAME_NAMES:
        return FRAME_NAMES[ftype]
    if ftype >= GREASE_FIRST:
        return "GREASE(0x%02x)" % ftype
    return "UNKNOWN(0x%02x)" % ftype


def flag_names(flags):
    names = []
    if flags & END_STREAM:
        names.append("END_STREAM")
    if flags & ~END_STREAM:
        names.append("0x%02x" % (flags & ~END_STREAM))
    return "|".join(names) or "-"


# --------------------------------------------------------------------------
# Frame header
# --------------------------------------------------------------------------

def pack_header(length, ftype, flags, stream_id):
    if not 0 <= length <= MAX_LENGTH:
        raise ValueError("frame length %d does not fit in 24 bits" % length)
    if not 0 <= stream_id <= MAX_STREAM_ID:
        raise ValueError("stream id %d does not fit in 24 bits" % stream_id)
    return (length.to_bytes(3, "big") + bytes((ftype & 0xFF, flags & 0xFF))
            + stream_id.to_bytes(3, "big"))


def unpack_header(raw):
    if len(raw) != FRAME_HEADER_LEN:
        raise ValueError("frame header must be 8 bytes")
    return FrameHeader(int.from_bytes(raw[0:3], "big"), raw[3], raw[4],
                       int.from_bytes(raw[5:8], "big"))


def build_frame(ftype, flags, stream_id, payload=b""):
    return pack_header(len(payload), ftype, flags, stream_id) + payload


# --------------------------------------------------------------------------
# Header block
# --------------------------------------------------------------------------

def _validate_name(name):
    raw = name.encode("ascii", "replace")
    if not 1 <= len(raw) <= 255:
        raise Malformed("header name length must be 1-255, got %d" % len(raw))
    if not set(raw) <= _TCHAR:
        raise Malformed("header name %r is not a lower-case token" % name)
    return raw


def _validate_value(raw, name):
    if len(raw) > 0xFFFF:
        raise Malformed("value of %r longer than 65535 bytes" % name)
    if _BAD_VALUE_BYTES & set(raw):
        raise Malformed("value of %r contains CR, LF or NUL" % name)
    return raw


def encode_fields(fields):
    """Encode [(name, value), ...]. Names in the static table MUST be indexed."""
    out = bytearray()
    for name, value in fields:
        name = name.strip().lower()
        raw_value = value if isinstance(value, bytes) else str(value).encode("utf-8")
        _validate_value(raw_value, name)
        index = STATIC_INDEX.get(name)
        if index is not None:
            out.append(index)
        else:
            raw_name = _validate_name(name)
            out.append(LITERAL)
            out.append(len(raw_name))
            out += raw_name
        out += len(raw_value).to_bytes(2, "big")
        out += raw_value
    return bytes(out)


def walk_fields(block, base=0):
    """Yield every Field in a header block, including ones we must skip.

    Fields with a reserved static index (0x0B-0xFF) come back with
    name=None: their value is still length-prefixed, so a v1 receiver can
    step over them cleanly (SPEC 6).
    """
    i, end = 0, len(block)

    def need(n, what):
        if i + n > end:
            raise Malformed("header block truncated in %s at byte %d"
                            % (what, base + i))

    while i < end:
        start = i
        index = block[i]
        i += 1
        if index == LITERAL:
            need(1, "name length")
            nlen = block[i]
            i += 1
            if nlen == 0:
                raise Malformed("literal header name of length 0 at byte %d"
                                % (base + start))
            need(nlen, "name")
            name = block[i:i + nlen].decode("ascii", "replace")
            _validate_name(name)
            if block[i:i + nlen] != name.encode("ascii"):
                raise Malformed("header name is not ASCII")
            i += nlen
        elif index <= STATIC_LAST:
            name = STATIC_TABLE[index]
        else:
            name = None
        need(2, "value length")
        vlen = int.from_bytes(block[i:i + 2], "big")
        i += 2
        need(vlen, "value")
        raw_value = bytes(block[i:i + vlen])
        i += vlen
        _validate_value(raw_value, name or "?")
        yield Field(base + start, index, name,
                    raw_value.decode("utf-8", "surrogateescape"))


def decode_fields(block):
    return [(f.name, f.value) for f in walk_fields(block) if f.name is not None]


def get_field(fields, name, default=None):
    for n, v in fields:
        if n == name:
            return v
    return default


# --------------------------------------------------------------------------
# REQUEST / RESPONSE / GOAWAY payloads
# --------------------------------------------------------------------------

def encode_request(method, path, fields=()):
    code = method if isinstance(method, int) else METHOD_CODES[method.upper()]
    raw_path = path.encode("utf-8")
    if not raw_path.startswith(b"/"):
        raise ValueError("path must start with '/'")
    if len(raw_path) > 0xFFFF:
        raise ValueError("path longer than 65535 bytes")
    return (bytes((code,)) + len(raw_path).to_bytes(2, "big") + raw_path
            + encode_fields(fields))


def decode_request(payload):
    if len(payload) < 3:
        raise Malformed("REQUEST payload is %d bytes; the minimum is 3"
                        % len(payload))
    code = payload[0]
    plen = int.from_bytes(payload[1:3], "big")
    if 3 + plen > len(payload):
        raise Malformed("path length %d exceeds the %d bytes left in the frame"
                        % (plen, len(payload) - 3))
    raw_path = bytes(payload[3:3 + plen])
    try:
        path = raw_path.decode("utf-8")
    except UnicodeDecodeError:
        raise Malformed("path is not valid UTF-8")
    if not path.startswith("/"):
        raise Malformed("path %r does not start with '/'" % path[:40])
    if "\x00" in path:
        raise Malformed("path contains NUL")
    path, _, query = path.partition("?")
    fields = decode_fields(payload[3 + plen:])
    return Request(code, METHODS.get(code), path, query, fields)


def encode_response(status, fields=()):
    if not 100 <= status <= 599:
        raise ValueError("status %d out of range" % status)
    return status.to_bytes(2, "big") + encode_fields(fields)


def decode_response(payload):
    if len(payload) < 2:
        raise Malformed("RESPONSE payload is %d bytes; the minimum is 2"
                        % len(payload))
    status = int.from_bytes(payload[0:2], "big")
    if not 100 <= status <= 599:
        raise Malformed("status %d out of range 100-599" % status)
    return Response(status, decode_fields(payload[2:]))


def encode_goaway(code, reason=""):
    return code.to_bytes(2, "big") + reason.encode("utf-8")


def decode_goaway(payload):
    if len(payload) < 2:
        return PROTOCOL_ERROR, "short GOAWAY"
    return (int.from_bytes(payload[0:2], "big"),
            bytes(payload[2:]).decode("utf-8", "replace"))
