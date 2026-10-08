"""Hexdumps and field-by-field annotation of BHTP bytes."""

from . import protocol as P


def hexdump(data, prefix="", limit=None):
    """Classic 16-bytes-per-line dump: offset, hex in two groups, ASCII."""
    lines = []
    shown = data if limit is None else data[:limit]
    for off in range(0, len(shown), 16):
        row = shown[off:off + 16]
        hexes = " ".join("%02x" % b for b in row[:8])
        if len(row) > 8:
            hexes += "  " + " ".join("%02x" % b for b in row[8:])
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append("%s%04x  %-49s |%s|" % (prefix, off, hexes, text))
    if limit is not None and len(data) > limit:
        lines.append("%s....  (%d more bytes not shown)"
                     % (prefix, len(data) - limit))
    return lines


def _fmt(raw):
    return " ".join("%02x" % b for b in raw)


def annotate_preface(raw):
    rows = [(0, raw[0:1], "magic", "0x89: high bit set, never valid ASCII "
             "- a text HTTP peer fails fast"),
            (1, raw[1:5], "magic", "\"BHTP\""),
            (5, raw[5:7], "magic", "CR LF - catches line-ending mangling"),
            (7, raw[7:8], "version", "%d" % raw[7])]
    return rows


def annotate_frame(raw):
    """Return [(offset, bytes, field, meaning)] for one complete frame."""
    hdr = P.unpack_header(raw[:8])
    payload = raw[8:]
    rows = [(0, raw[0:3], "length", "%d payload bytes" % hdr.length),
            (3, raw[3:4], "type", P.frame_name(hdr.type)),
            (4, raw[4:5], "flags", P.flag_names(hdr.flags)),
            (5, raw[5:8], "stream id", "%d" % hdr.stream_id)]
    base = 8
    fields_at = None
    if hdr.type == P.REQUEST and len(payload) >= 3:
        plen = int.from_bytes(payload[1:3], "big")
        rows.append((8, payload[0:1], "method",
                     P.METHODS.get(payload[0], "unknown 0x%02x" % payload[0])))
        rows.append((9, payload[1:3], "path length", "%d" % plen))
        rows.append((11, payload[3:3 + plen], "path",
                     repr(bytes(payload[3:3 + plen]).decode("utf-8", "replace"))))
        fields_at = 3 + plen
    elif hdr.type == P.RESPONSE and len(payload) >= 2:
        status = int.from_bytes(payload[0:2], "big")
        rows.append((8, payload[0:2], "status",
                     "%d %s" % (status, P.REASONS.get(status, ""))))
        fields_at = 2
    elif hdr.type == P.GOAWAY and len(payload) >= 2:
        code = int.from_bytes(payload[0:2], "big")
        rows.append((8, payload[0:2], "error code",
                     P.ERROR_NAMES.get(code, "0x%04x" % code)))
        if len(payload) > 2:
            rows.append((10, payload[2:], "reason",
                         repr(bytes(payload[2:]).decode("utf-8", "replace"))))
    elif payload:
        what = "body bytes" if hdr.type == P.DATA else "skipped, unknown type"
        rows.append((8, payload, "payload", "%d %s" % (len(payload), what)))

    if fields_at is not None:
        block = payload[fields_at:]
        for f in P.walk_fields(block):
            i = f.offset
            if f.index == P.LITERAL:
                nlen = block[i + 1]
                v_at = i + 2 + nlen
                rows.append((base + fields_at + i, block[i:i + 1], "  index",
                             "0x00 = literal name follows"))
                rows.append((base + fields_at + i + 1, block[i + 1:i + 2],
                             "  name length", "%d" % nlen))
                rows.append((base + fields_at + i + 2, block[i + 2:v_at],
                             "  name", repr(f.name)))
            else:
                v_at = i + 1
                meaning = ("static[%d] = %s" % (f.index, f.name) if f.name
                           else "reserved index, field skipped")
                rows.append((base + fields_at + i, block[i:i + 1], "  index",
                             meaning))
            vlen = int.from_bytes(block[v_at:v_at + 2], "big")
            rows.append((base + fields_at + v_at, block[v_at:v_at + 2],
                         "  value length", "%d" % vlen))
            rows.append((base + fields_at + v_at + 2,
                         block[v_at + 2:v_at + 2 + vlen], "  value",
                         repr(f.value)))
    return rows


def describe(hdr, payload):
    """Short human-readable decode of a frame, for -v output."""
    if payload is None:
        return ["(payload of %d bytes discarded unread)" % hdr.length]
    try:
        if hdr.type == P.REQUEST:
            req = P.decode_request(payload)
            target = req.path + ("?" + req.query if req.query else "")
            out = ["%s %s" % (req.method or "method 0x%02x" % req.method_code,
                              target)]
            out += ["%s: %s" % kv for kv in req.fields]
            return out
        if hdr.type == P.RESPONSE:
            resp = P.decode_response(payload)
            out = ["%d %s" % (resp.status, P.REASONS.get(resp.status, ""))]
            out += ["%s: %s" % kv for kv in resp.fields]
            return out
        if hdr.type == P.GOAWAY:
            code, reason = P.decode_goaway(payload)
            return ["%s %s" % (P.ERROR_NAMES.get(code, "0x%04x" % code),
                               repr(reason))]
        if hdr.type == P.DATA:
            return ["%d body bytes" % len(payload)]
        return ["unknown type: skipped (%d bytes)" % len(payload)]
    except P.Malformed as e:
        return ["MALFORMED: %s" % e]


def render_annotation(rows, width=24):
    """Rows -> fixed-width text table (used to build HEXDUMP.md)."""
    out = []
    for off, raw, field, meaning in rows:
        hexes = _fmt(raw)
        if len(raw) > width // 3 + 4:
            hexes = _fmt(raw[:6]) + " ...(%d)" % len(raw)
        out.append("%04x  %-26s %-15s %s" % (off, hexes, field, meaning))
    return out
