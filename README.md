# BHTP/1: HTTP, in binary

*Network Architecture course project · Siddhant Prasad*

BHTP is a binary framing of HTTP that I designed for this project. It has a fixed 8-byte
frame header, a ten-entry static header table, length-prefixed literals, and one rule that
leaves room for a version 2: **a receiver MUST skip any frame type it does not know.** This
repository contains the spec, a server (`bserve`), a client (`bcurl`), and an annotated
hexdump of real traffic.

## What is handed in

| # | Deliverable | Where |
|---|---|---|
| 1 | **The spec.** Two pages, written so a stranger can implement it. | [`SPEC.md`](SPEC.md) · printable [`SPEC.pdf`](SPEC.pdf) |
| 2 | **The program.** Track 1 is the server, track 2 is the client. | [`bserve`](bserve), [`bcurl`](bcurl) → [`bhtp/`](bhtp) |
| 3 | **An annotated hexdump** of one complete request and response | [`HEXDUMP.md`](HEXDUMP.md) |
| + | The defence of every field width, including why HTTP/2 chose 24/8/8/31 | [`RATIONALE.md`](RATIONALE.md) |
| + | 66 tests: raw-byte conformance, a spec-only fake server, fuzzing, and checks that the docs match the bytes | [`tests/`](tests) |

## The frame header, at a glance

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-----------------------------------------------+---------------+
|                  Length (24)                  |   Type (8)    |
+---------------+-----------------------------------------------+
|   Flags (8)   |                 Stream ID (24)                |
+---------------+-----------------------------------------------+
```

The header is 8 bytes, one 64-bit word. The types are REQUEST `01`, RESPONSE `02`, DATA
`03`, GOAWAY `04`, and GREASE `F0`–`FF`. Each connection opens with the 8-byte preface
`89 42 48 54 50 0D 0A 01`, which is `0x89`, `"BHTP"`, CR LF, and the version byte.

## Quick start

You need Python 3.8 or newer and nothing else (standard library only, nothing to build).

```sh
# Track 1: the server
./bserve ./www 9000

# Track 2: the client, in another terminal
./bcurl -v localhost:9000/index.html
```

On Windows, `bserve.cmd` and `bcurl.cmd` do the same thing from cmd or PowerShell
(`.\bcurl -v localhost:9000/index.html`). You can also run `python bcurl ...` directly.

### bserve

```
./bserve ROOT [PORT]            serve ROOT on PORT (default 9000)
  --host ADDR                   bind address (default 0.0.0.0)
  -v                            hexdump every frame to stderr
  -q                            no access log
  --idle-timeout S              GOAWAY after S seconds idle (default 30)
  --grease                      send a random unknown frame before every response
```

What it does:

- accepts any number of concurrent connections (one thread each)
- reads binary REQUEST frames and maps each path to a file under ROOT (`/dir/` serves
  `dir/index.html`)
- replies with RESPONSE and DATA frames in 16 KiB chunks. It answers **404** when the file
  is not there and **400** when the frame is malformed, and either way it **keeps the
  connection open**.
- also returns 304 (`if-none-match`), 405, 431 and 501, and answers OPTIONS
- refuses `..` paths and symlinks that lead out of the root
- answers a plain HTTP/1.1 client in text, so `curl localhost:9000` explains what this port
  is instead of hanging

### bcurl

```
./bcurl [options] URL [URL ...]   URL = host[:port]/path | bhtp://host[:port]/path | /path
  -v                              hexdump every frame sent and received (stderr)
  -i / -I                         include the response head / send HEAD
  -X METHOD   -H 'name: value'    method, extra header (sent as a literal)
  --grease                        send a random unknown frame before every request
  --dump-limit N                  with -v, show only N bytes of each DATA frame
```

What it does:

- builds the binary REQUEST frame and writes the body to **stdout** (byte-exact, so it is
  safe to pipe)
- writes the trace to **stderr**
- with `-v`, prints a hexdump and a decoded summary of **every frame**, including the
  prefaces and GOAWAY
- **never opens a second connection.** `./bcurl host:9000/a /b /c` fetches all three over
  one TCP connection. URLs that point at different hosts are rejected before anything is
  sent.
- exit status: `0` ok · `2` usage · `3` connection or protocol error · **`4` on 4xx** ·
  **`5` on 5xx**

### What `-v` looks like

```
$ ./bcurl -v localhost:9000/hello.txt
* connecting to localhost port 9000
* connected to 127.0.0.1 port 9000
> PREFACE  8 bytes
>   0000  89 42 48 54 50 0d 0a 01                           |.BHTP...|
> REQUEST stream=1 flags=END_STREAM length=48
>   0000  00 00 30 01 01 00 00 01  01 00 0a 2f 68 65 6c 6c  |..0......../hell|
>   0010  6f 2e 74 78 74 01 00 0e  6c 6f 63 61 6c 68 6f 73  |o.txt...localhos|
>   0020  74 3a 39 30 30 30 02 00  09 62 63 75 72 6c 2f 31  |t:9000...bcurl/1|
>   0030  2e 30 03 00 03 2a 2f 2a                           |.0...*/*|
>     GET /hello.txt
>     host: localhost:9000
>     user-agent: bcurl/1.0
>     accept: */*
< PREFACE  8 bytes
< RESPONSE stream=1 flags=- length=128
<   0000  00 00 80 02 00 00 00 01  00 c8 06 00 0a 62 73 65  |.............bse|
<   ...
<     200 OK
<     content-type: text/plain; charset=utf-8
<     content-length: 20
< DATA stream=1 flags=END_STREAM length=20
<   0000  00 00 14 03 01 00 00 01  68 65 6c 6c 6f 2c 20 62  |........hello, b|
<   0010  69 6e 61 72 79 20 77 6f  72 6c 64 0a              |inary world.|
hello, binary world
> GOAWAY stream=0 flags=- length=6
```

## Tests

```sh
python -m unittest discover -s tests -v
```

| File | What it proves |
|---|---|
| `test_protocol.py` | The codec and every malformed-input path. The spec's byte examples are reproduced exactly. |
| `test_server.py` | bserve, driven with **hand-assembled bytes** taken from the spec (not built with the project's own encoder). It covers keep-alive (50 requests, 1 connection), pipelining, 400/404/405/431/501/304, the connection surviving every 400, unknown frame types (including a 3 MiB one), reserved header indexes, the bad-preface, version and text-HTTP paths, idle timeout, concurrency, and 150 rounds of random-garbage fuzzing. |
| `test_client.py` | bcurl, run as a real subprocess against bserve **and against an independent fake server written only from the spec.** The fake server sends legal oddities that bserve never sends. The tests also check exit codes and that exactly one TCP connection is opened. |
| `test_docs.py` | The bytes printed in SPEC.md and HEXDUMP.md are exactly what the code emits. |

The suite uses only the standard library and runs on Linux, macOS and Windows.

## Interop: writing your own client or server

The brief says *"A client that only works against your own server is an implementation,
not a protocol."* If you implement BHTP from [`SPEC.md`](SPEC.md) alone, test it against
this one as follows:

1. Run `./bserve ./www 9000 -v`. It shows every frame you send, decoded, and tells you what
   is wrong with any frame it rejects in the 400 body.
2. Run `./bcurl -v --grease yourhost:9000/` against your server. Your server must skip the
   GREASE frames and still answer.
3. Run `./bserve --grease` against your client. Your client must skip the unknown frames
   the server sends.
4. Compare your bytes with SPEC §9 and HEXDUMP.md. Both use one canonical encoding, so
   matching bytes are a strong check.

## Repository layout

```
SPEC.md / SPEC.pdf    the protocol: the main deliverable
RATIONALE.md          why each width and choice; HTTP/2's 24/8/8/31 explained
HEXDUMP.md            a captured exchange, annotated byte by byte
bserve, bcurl         launchers (shell/Python polyglots); *.cmd for Windows
bhtp/protocol.py      every wire constant and codec: the only place bytes are defined
bhtp/wire.py          frame I/O on sockets: exact reads, clean skipping
bhtp/server.py        bserve
bhtp/client.py        bcurl
bhtp/hexdump.py       hexdumps and field-by-field annotation
tools/capture.py      regenerates the HEXDUMP.md capture
tools/make_pdf.py     renders SPEC.md to SPEC.pdf
www/                  demo docroot: html, css, a png, a UTF-8 file name
tests/                66 tests
```
