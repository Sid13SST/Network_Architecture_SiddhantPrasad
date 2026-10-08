"""Capture one complete BHTP/1 exchange and print it annotated, field by field.

    python tools/capture.py [path]        (default path: /hello.txt)

Starts bserve on ./www in-process, runs one request through the same code
bcurl uses, records every byte in both directions, and prints a Markdown
table per frame. HEXDUMP.md was produced this way and then annotated by hand.
"""

import argparse
import os
import sys
import threading

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from bhtp import client, server  # noqa: E402
from bhtp import protocol as P  # noqa: E402
from bhtp.hexdump import annotate_frame, annotate_preface, hexdump  # noqa: E402


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/hello.txt"
    cfg = argparse.Namespace(root=os.path.realpath(os.path.join(HERE, "www")),
                             verbose=False, quiet=True, idle_timeout=5,
                             grease=False, dump_limit=None)
    listener = server.make_listener("127.0.0.1", 0)
    stop = threading.Event()
    threading.Thread(target=server.serve, args=(cfg, listener, stop),
                     daemon=True).start()

    captured = []
    args = client.parse_args(["-v", "localhost:9000" + path])
    c = client.Client(args)
    c.out = open(os.devnull, "wb")
    c.trace = lambda d, raw, hdr, payload: captured.append((d, raw, hdr))
    c.info = lambda msg: None
    c.connect("127.0.0.1", listener.getsockname()[1])
    c.fetch(1, "GET", "localhost:9000", path, [])
    c.close()
    stop.set()

    total = {">": 0, "<": 0}
    for direction, raw, hdr in captured:
        total[direction] += len(raw)
        who = "client -> server" if direction == ">" else "server -> client"
        name = "PREFACE" if hdr is None else P.frame_name(hdr.type)
        print("### %s  (%s, %d bytes)\n" % (name, who, len(raw)))
        print("```")
        print("\n".join(hexdump(raw)))
        print("```\n")
        print("| offset | bytes | field | meaning |")
        print("|---|---|---|---|")
        rows = annotate_preface(raw) if hdr is None else annotate_frame(raw)
        for off, b, field, meaning in rows:
            hexes = " ".join("%02x" % x for x in b)
            if len(b) > 12:
                hexes = " ".join("%02x" % x for x in b[:8]) + " ... (%d bytes)" % len(b)
            print("| `%04x` | `%s` | %s | %s |" % (
                off, hexes, field.strip(), meaning.replace("|", "\\|")))
        print()
    print("Totals: client sent %d bytes, server sent %d bytes."
          % (total[">"], total["<"]))


if __name__ == "__main__":
    main()
