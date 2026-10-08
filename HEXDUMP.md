# Annotated hexdump: one complete request and response

The bytes below were **captured from a real run**: `python tools/capture.py /hello.txt`,
which runs bserve on `./www` and sends the request through bcurl's own code path. You can
reproduce them with `./bcurl -v localhost:9000/hello.txt`. Only the two date values will
differ. Every byte is accounted for: each frame is first shown as a raw dump and then
explained field by field. The offsets in the tables are offsets within that frame.

**Exchange:** `GET /hello.txt` on stream 1, answered `200 OK` with a 20-byte body, then a
polite close.

```
client                                                   server
  | -- PREFACE   8 B  89 42 48 54 50 0d 0a 01 ------------> |
  | -- REQUEST  56 B  GET /hello.txt, stream 1, END ------> |   (same TCP write; no RTT wait)
  | <------------ PREFACE   8 B  89 42 48 54 50 0d 0a 01 -- |
  | <------------ RESPONSE 136 B  200, 6 header fields ---- |
  | <------------ DATA      28 B  20 body bytes, END ------ |
  | -- GOAWAY   14 B  NO_ERROR "done" --------------------> |
```

Client → server, all 78 bytes (frame boundaries marked `|`):

```
89 42 48 54 50 0d 0a 01 | 00 00 30 01 01 00 00 01 01 00 0a 2f 68 65 6c 6c 6f 2e 74 78 74
01 00 0e 6c 6f 63 61 6c 68 6f 73 74 3a 39 30 30 30 02 00 09 62 63 75 72 6c 2f 31 2e 30
03 00 03 2a 2f 2a | 00 00 06 04 00 00 00 00 00 00 64 6f 6e 65
```

The server sends 172 bytes: preface (8) + RESPONSE (136) + DATA (28). All six frames are
dissected below.

## Frame by frame

### 1. PREFACE  (client -> server, 8 bytes)

```
0000  89 42 48 54 50 0d 0a 01                           |.BHTP...|
```

| offset | bytes | field | meaning |
|---|---|---|---|
| `0000` | `89` | magic | 0x89: high bit set, never valid ASCII - a text HTTP peer fails fast |
| `0001` | `42 48 54 50` | magic | "BHTP" |
| `0005` | `0d 0a` | magic | CR LF - catches line-ending mangling |
| `0007` | `01` | version | 1 |

**Read it:** `0x89` is not ASCII, so a text-HTTP server sees garbage at once. `"BHTP"` is the name. `0d 0a` would be mangled by anything that rewrites line endings. The last byte, `01`, is the protocol version. It is stated here, once per connection, and that is why the frame header does not carry a version. The client does **not** wait for the server's preface. Its REQUEST follows in the same write, so the handshake costs no round trip.

### 2. PREFACE  (server -> client, 8 bytes)

```
0000  89 42 48 54 50 0d 0a 01                           |.BHTP...|
```

| offset | bytes | field | meaning |
|---|---|---|---|
| `0000` | `89` | magic | 0x89: high bit set, never valid ASCII - a text HTTP peer fails fast |
| `0001` | `42 48 54 50` | magic | "BHTP" |
| `0005` | `0d 0a` | magic | CR LF - catches line-ending mangling |
| `0007` | `01` | version | 1 |

**Read it:** the server sends back the same 8 bytes. That tells the client that it is talking to BHTP/1 and not, for example, an HTTP/1.1 server (bcurl exits with status 3 if the bytes differ).

### 3. REQUEST  (client -> server, 56 bytes)

```
0000  00 00 30 01 01 00 00 01  01 00 0a 2f 68 65 6c 6c  |..0......../hell|
0010  6f 2e 74 78 74 01 00 0e  6c 6f 63 61 6c 68 6f 73  |o.txt...localhos|
0020  74 3a 39 30 30 30 02 00  09 62 63 75 72 6c 2f 31  |t:9000...bcurl/1|
0030  2e 30 03 00 03 2a 2f 2a                           |.0...*/*|
```

| offset | bytes | field | meaning |
|---|---|---|---|
| `0000` | `00 00 30` | length | 48 payload bytes |
| `0003` | `01` | type | REQUEST |
| `0004` | `01` | flags | END_STREAM |
| `0005` | `00 00 01` | stream id | 1 |
| `0008` | `01` | method | GET |
| `0009` | `00 0a` | path length | 10 |
| `000b` | `2f 68 65 6c 6c 6f 2e 74 78 74` | path | '/hello.txt' |
| `0015` | `01` | index | static[1] = host |
| `0016` | `00 0e` | value length | 14 |
| `0018` | `6c 6f 63 61 6c 68 6f 73 ... (14 bytes)` | value | 'localhost:9000' |
| `0026` | `02` | index | static[2] = user-agent |
| `0027` | `00 09` | value length | 9 |
| `0029` | `62 63 75 72 6c 2f 31 2e 30` | value | 'bcurl/1.0' |
| `0032` | `03` | index | static[3] = accept |
| `0033` | `00 03` | value length | 3 |
| `0035` | `2a 2f 2a` | value | '*/*' |

**Read it:** `00 00 30`: 48 payload bytes, and 8 + 48 = 56 bytes on the wire. `01` = REQUEST. Flags `01` = END_STREAM, so no request body follows. `00 00 01` = stream 1, the first request on this connection.
The payload starts at offset `0x08`. Method `01` = GET. `00 0a` = a 10-byte path, `/hello.txt`, sent as raw UTF-8 with no percent-encoding.
Then come three header fields. Each one is an **index byte**, a **16-bit value length** and the value. All three names are in the static table (`01` host, `02` user-agent, `03` accept), so each name costs 1 byte. The equivalent HTTP/1.1 text request is 85 bytes.

### 4. RESPONSE  (server -> client, 136 bytes)

```
0000  00 00 80 02 00 00 00 01  00 c8 06 00 0a 62 73 65  |.............bse|
0010  72 76 65 2f 31 2e 30 07  00 1d 54 68 75 2c 20 30  |rve/1.0...Thu, 0|
0020  38 20 4f 63 74 20 32 30  32 36 20 31 36 3a 35 31  |8 Oct 2026 16:51|
0030  3a 34 33 20 47 4d 54 04  00 19 74 65 78 74 2f 70  |:43 GMT...text/p|
0040  6c 61 69 6e 3b 20 63 68  61 72 73 65 74 3d 75 74  |lain; charset=ut|
0050  66 2d 38 05 00 02 32 30  08 00 1d 54 68 75 2c 20  |f-8...20...Thu, |
0060  30 38 20 4f 63 74 20 32  30 32 36 20 31 32 3a 33  |08 Oct 2026 12:3|
0070  38 3a 34 30 20 47 4d 54  09 00 0d 22 31 34 2d 36  |8:40 GMT..."14-6|
0080  61 63 37 38 65 64 30 22                           |ac78ed0"|
```

| offset | bytes | field | meaning |
|---|---|---|---|
| `0000` | `00 00 80` | length | 128 payload bytes |
| `0003` | `02` | type | RESPONSE |
| `0004` | `00` | flags | - |
| `0005` | `00 00 01` | stream id | 1 |
| `0008` | `00 c8` | status | 200 OK |
| `000a` | `06` | index | static[6] = server |
| `000b` | `00 0a` | value length | 10 |
| `000d` | `62 73 65 72 76 65 2f 31 2e 30` | value | 'bserve/1.0' |
| `0017` | `07` | index | static[7] = date |
| `0018` | `00 1d` | value length | 29 |
| `001a` | `54 68 75 2c 20 30 38 20 ... (29 bytes)` | value | 'Thu, 08 Oct 2026 16:51:43 GMT' |
| `0037` | `04` | index | static[4] = content-type |
| `0038` | `00 19` | value length | 25 |
| `003a` | `74 65 78 74 2f 70 6c 61 ... (25 bytes)` | value | 'text/plain; charset=utf-8' |
| `0053` | `05` | index | static[5] = content-length |
| `0054` | `00 02` | value length | 2 |
| `0056` | `32 30` | value | '20' |
| `0058` | `08` | index | static[8] = last-modified |
| `0059` | `00 1d` | value length | 29 |
| `005b` | `54 68 75 2c 20 30 38 20 ... (29 bytes)` | value | 'Thu, 08 Oct 2026 12:38:40 GMT' |
| `0078` | `09` | index | static[9] = etag |
| `0079` | `00 0d` | value length | 13 |
| `007b` | `22 31 34 2d 36 61 63 37 ... (13 bytes)` | value | '"14-6ac78ed0"' |

**Read it:** 128 payload bytes. `02` = RESPONSE. Flags `00`: END_STREAM is **not** set, so a body follows in DATA frames. `00 00 01` = an answer to stream 1.
Status `00 c8` = 200. Six header fields follow, all static-table names (indexes 6, 7, 4, 5, 8, 9). The 2-byte value-length prefix tells the client exactly where each value ends, so no `: ` separators or CR LF terminators are needed. `content-length: 20` lets the client check the body it is about to receive.

### 5. DATA  (server -> client, 28 bytes)

```
0000  00 00 14 03 01 00 00 01  68 65 6c 6c 6f 2c 20 62  |........hello, b|
0010  69 6e 61 72 79 20 77 6f  72 6c 64 0a              |inary world.|
```

| offset | bytes | field | meaning |
|---|---|---|---|
| `0000` | `00 00 14` | length | 20 payload bytes |
| `0003` | `03` | type | DATA |
| `0004` | `01` | flags | END_STREAM |
| `0005` | `00 00 01` | stream id | 1 |
| `0008` | `68 65 6c 6c 6f 2c 20 62 ... (20 bytes)` | payload | 20 body bytes |

**Read it:** 20 payload bytes. `03` = DATA. Flags `01` = END_STREAM, so this frame is the last of the response, and the client now knows the body is complete without closing the connection. Stream 1. The payload is the file `www/hello.txt`, byte for byte: `hello, binary world
`. Its 20 bytes match `content-length`.

### 6. GOAWAY  (client -> server, 14 bytes)

```
0000  00 00 06 04 00 00 00 00  00 00 64 6f 6e 65        |..........done|
```

| offset | bytes | field | meaning |
|---|---|---|---|
| `0000` | `00 00 06` | length | 6 payload bytes |
| `0003` | `04` | type | GOAWAY |
| `0004` | `00` | flags | - |
| `0005` | `00 00 00` | stream id | 0 |
| `0008` | `00 00` | error code | NO_ERROR |
| `000a` | `64 6f 6e 65` | reason | 'done' |

**Read it:** 6 payload bytes. `04` = GOAWAY. Stream `00 00 00`, because GOAWAY applies to the connection rather than to one request. Error code `00 00` = NO_ERROR, and the reason is `done`. bcurl sends this to close politely. bserve reads it and closes its side. The connection stayed open for the whole exchange. If bcurl had been given more URLs, streams 2, 3, … would have reused this connection before the GOAWAY (`./bcurl host/a /b /c`).

## Totals

| | bytes | HTTP/1.1 text equivalent |
|---|---|---|
| client → server | 8 preface + 56 request + 14 goaway = **78** | 85 (request only) |
| server → client | 8 preface + 136 response + 28 data = **172** | 224 (head 204 + body 20) |

## Bonus 1: a malformed request gets a 400, and the connection stays open

The REQUEST below claims a 255-byte path (`00 ff`), but only 2 bytes follow. The frame's
Length (`00 00 05`) is still correct, so the server knows exactly where the frame ends. This
is a **stream error**: the server answers 400 on stream 1, and stream 2 is served normally on
the same connection (verified by `test_400_malformed_frames`).

```
> 00 00 05 01 01 00 00 01  01 00 ff 2f 78       len=5 REQUEST END_STREAM sid=1 | GET, path len 255 (!), "/x"
< 00 00 50 02 00 00 00 01  01 90 06 00 0a ...   len=80 RESPONSE sid=1 | status 0x0190 = 400, server, date, ...
< 00 00 47 03 01 00 00 01  34 30 30 20 42 ...   len=71 DATA END_STREAM sid=1 | "400 Bad Request: path length 255
                                                  exceeds the 2 bytes left in the frame
"
> 00 00 0e 01 01 00 00 02  01 00 0b 2f 69 ...   len=14 REQUEST END_STREAM sid=2 | GET /index.html  -> 200
```

## Bonus 2: an unknown frame type is skipped cleanly

```
> 00 00 03 7f ff 00 00 00  aa bb cc             len=3 type=0x7F (unknown) flags=0xFF sid=0
```

bserve reads the 8-byte header and sees a type it does not know. It reads and discards
exactly 3 bytes, then reads the next frame header. It does not reply or close, and it does
not look at the flags or the stream id. That is all of SPEC §4.
