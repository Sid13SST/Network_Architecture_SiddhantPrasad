# Design rationale: defending the widths

SPEC.md says *what* goes on the wire. This document explains *why*. The brief asked us to
pick our own header fields and widths, defend them, and explain why HTTP/2 chose
24 / 8 / 8 / 31.

## 1. Why HTTP/2 chose 24 / 8 / 8 / (1 + 31)

HTTP/2's 9-byte frame header (RFC 9113 §4.1) is `Length 24 | Type 8 | Flags 8 | R 1 | Stream 31`.

| Field | Width | Why HTTP/2 picked it |
|---|---|---|
| Length | 24 | HTTP/2 multiplexes many streams over one TCP connection, so a single huge frame would block every other stream behind it (head-of-line blocking *inside* the connection). A 16-bit length (64 KiB maximum) was considered too small for bulk transfer. A 32-bit length would let one frame tie up the connection for gigabytes. 24 bits gives a hard ceiling of 16 MiB, and the default limit is 16 KiB (`SETTINGS_MAX_FRAME_SIZE`). A peer must opt in before it receives anything larger, so frames stay small enough to interleave. |
| Type | 8 | HTTP/2 defines 10 types. 256 leaves a large space for extensions (RFC 7540 §5.5, "Extending HTTP/2"), and unknown types MUST be ignored. One byte is the smallest addressable unit anyway. |
| Flags | 8 | The flags mean different things for each type (END_STREAM, END_HEADERS, PADDED, PRIORITY, ACK). Eight bits covers all of them with one byte. |
| R | 1 | A reserved bit with "MUST be ignored" semantics. It was kept for an unknown future use, and in practice no extension has ever used it. |
| Stream ID | 31 | Streams are never reused on a connection. The client opens odd ids and the server opens even ids (server push), so each side has 2^30 ids. HTTP/2 connections are long-lived (browsers keep them for minutes), so 31 bits ensures ids are never the reason a connection has to close. 31 + 1 fits a 32-bit word. |

Total: 9 bytes. HTTP/2 accepted an unaligned 9-byte header to get these properties. The
odd size is a known wart: no implementation reads it as a single machine word.

## 2. What BHTP chose: 24 / 8 / 8 / 24 = 8 bytes

| Field | BHTP | Defence | What it costs |
|---|---|---|---|
| Length | **24** | We keep HTTP/2's reasoning. The receiver knows the payload size before it reads a byte, so it can reject or skip a frame without buffering it (bserve skips a 3 MiB unknown frame in 64 KiB chunks, see the tests). With 16 bits, a header block larger than 64 KiB would need a CONTINUATION frame, and CONTINUATION caused real HTTP/2 vulnerabilities (the 2024 "CONTINUATION flood"). With 32 bits, a peer could announce 4 GiB. | None |
| Type | **8** | v1 uses 4 of the 256 values. 236 are left for future versions and 16 (`0xF0`–`0xFF`) are GREASE. One byte is the smallest unit, and a 4-bit type would save nothing once the header is byte-aligned. | None |
| Flags | **8** | Only END_STREAM is defined, but each future frame type gets 7 more bits without a format change. | 7 unused bits today |
| Stream ID | **24** | v1 does not multiplex, but every request still gets an id. That way v2 can multiplex without changing the header, which is the main thing a binary framing layer should allow for. 2^24 = 16.7 million requests per connection, and bcurl sends a handful. We dropped HTTP/2's odd/even split (no server push) and the R bit (never used). | 16.7 M requests per connection. Past that, GOAWAY and reconnect. |
| *(total)* | **8 bytes** | One 64-bit word. `read(8)` returns the whole header, and every field sits on a byte boundary. A hexdump line holds two complete frame headers, which makes the annotated hexdump easy to read. | |

### What we left out of the header, on purpose

- **A version field.** The version is fixed for the life of a connection, so it belongs in
  the 8-byte connection preface (once per connection), not in every frame.
- **A magic number per frame.** The preface already provides one. Once both sides are in
  sync, Length keeps them in sync.
- **A checksum.** TCP already has one, and TLS (in a future version) adds a MAC.
- **Padding and priority.** HTTP/2's PADDED flag and priority fields served multiplexing
  and traffic-analysis needs that v1 does not have. HTTP/2's priority scheme was later
  deprecated anyway (RFC 9113 §5.3).

## 3. The header block: HPACK's first two ideas, without its state

HPACK (RFC 7541) has four mechanisms: a static table, length-prefixed string literals, a
**dynamic table**, and **Huffman coding**. BHTP takes the first two.

1. **The static table holds the ten names BHTP actually sends.** Three come from the
   client (`host`, `user-agent`, `accept`). Seven come from the server (`content-type`,
   `content-length`, `server`, `date`, `last-modified`, `etag`, `allow`). Each indexed name
   saves its full length, which is up to 14 bytes for `content-length`. A typical bserve
   response sends its 6 names in 6 bytes instead of 53.
2. **Everything else is length-prefixed:** an 8-bit name length (header names are short,
   and HTTP/2 implementations commonly limit them as well) and a 16-bit value length (64
   KiB, well above the 4–8 KiB value limits that real servers enforce).

**Why we left out the dynamic table and Huffman coding.** Both make the decoder *stateful*:
you cannot decode frame N without having decoded frames 1 to N−1. Our scheme is stateless.
Any frame can be decoded on its own, and that property is what makes three things possible:

- the "skip any unknown frame" rule (skipping a frame cannot corrupt any decoder state)
- the annotated hexdump (each frame's bytes can be explained on their own)
- the per-stream 400 that keeps the connection open (a bad header block cannot poison a
  shared table)

Shared compression state also has its own attack history: CRIME shaped HPACK's design, and
HPACK bombs followed. The cost is measured in §6.

**Why "MUST index" for table names.** If a field could be sent indexed or literal, two
correct implementations could produce different bytes for the same request. One canonical
encoding means the worked example in SPEC §9 is the only correct encoding. Receivers still
accept literals, so a lazy sender still interoperates.

**Why fixed widths instead of varints (QUIC/HPACK style).** A varint would save 1 byte on
values shorter than 128 bytes. In exchange, every length becomes a loop with a
continuation bit, and a byte can no longer be annotated by its offset alone. For a protocol
that a stranger must implement in an evening, fixed widths win.

**Reserved indexes 11–255 are skipped, not rejected.** A v2 can add `cache-control` as
index 11. A v1 receiver drops that one field and keeps everything else. This is the
frame-level skip rule applied to individual header fields.

## 4. Fixed positions for method, path and status

HTTP/2 sends method and path as pseudo-headers (`:method`, `:path`), which creates failure
modes such as "missing `:path`", "duplicate `:method`", and "pseudo-header after a regular
header". BHTP gives every REQUEST a method and a path, and every RESPONSE a status, so
these sit at fixed offsets: method at byte 0, status at bytes 0–1. A one-byte method code
costs 1 byte, where the text form costs 3–7. The unassigned method codes become **501**,
which is HTTP's own answer for "method not understood".

## 5. Other decisions

| Decision | Why |
|---|---|
| An 8-byte preface: `89 "BHTP" CR LF 01` | This is the PNG trick. `0x89` is not ASCII, so a text HTTP server rejects us at once, and bserve can tell that `GET ` is a text client and answer it in HTTP/1.1. CR LF catches anything that rewrites line endings. The client does not wait for the server's preface, so the handshake costs **zero round trips**. |
| Paths travel decoded | Length-prefixing makes percent-encoding unnecessary. Forbidding the receiver to decode again removes the "double-decoding" bug class (`%252e%252e` → `%2e%2e` → `..`). |
| Stream errors vs connection errors | Once Length has been honoured, framing is intact no matter how broken the payload is. So a malformed request costs one 400 and does **not** cost the connection. Only failures that break framing (EOF mid-frame, a bad preface) drop it. |
| No CR/LF/NUL in values | A BHTP→HTTP/1 gateway can never be made to inject a header line. |
| GREASE types `0xF0`–`0xFF` | From TLS (RFC 8701) and QUIC. An extension point that nobody exercises stops working before anyone needs it. `bcurl --grease` and `bserve --grease` send random unknown frames to exercise it. |
| No per-stream reset in v1 | If a file disappears after its 200 has been sent, the only honest option is GOAWAY. This gap is documented, and it is the first thing v2 would add. |

## 6. Measured cost (captured `GET /hello.txt`, see HEXDUMP.md)

| | HTTP/1.1 text | BHTP/1 | Saving |
|---|---|---|---|
| Request | 85 B | 56 B | 34 % |
| Response head | 204 B | 136 B | 33 % |
| Response head + 20-byte body | 224 B | 164 B (header + DATA frame) | 27 % |
| Per connection | 0 | 16 B of preface (8 each way), once | |

Most of the remaining bytes are values (`date` and `last-modified` alone take 58). HPACK's
dynamic table would remove them on repeated requests, and that is the trade we declined in
§3.

## 7. A path to version 2

1. The preface version byte becomes `02`, and a v2 server still answers a `01` client as v1.
2. **Multiplexing:** the stream ids already exist. The server stops serialising, and frames
   from different streams interleave.
3. **New frame types** from the unassigned range: `0x05` RST_STREAM (cancel one stream),
   `0x06` SETTINGS (negotiate frame size and table size), `0x07` PING. A v1 peer that
   receives any of them skips it, which is the rule this design is built around.
4. **New static-table entries** at index 11 and above. v1 receivers skip those fields.
