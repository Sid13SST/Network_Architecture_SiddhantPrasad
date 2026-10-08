"""Render SPEC.md to a printable two-page SPEC.pdf with headless Chrome/Edge.

    python tools/make_pdf.py [SPEC.md] [SPEC.pdf]

Handles exactly the Markdown subset the spec uses: headings, paragraphs,
lists, tables, fenced code, block quotes, `code`, **bold**, *italic*.
"""

import html
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CSS = """
@page { size: A4; margin: 11mm 12mm; }
body { font: 8.6pt/1.32 "Segoe UI", Helvetica, Arial, sans-serif; color: #111; }
h1 { font-size: 13pt; margin: 0 0 1px; }
h2 { font-size: 9.6pt; margin: 7px 0 2px; border-bottom: 1px solid #bbb;
     break-after: avoid; page-break-after: avoid; }
p, ul { margin: 2px 0 3px; }
ul { padding-left: 15px; }
li { margin: 0; }
pre { font: 7.5pt/1.22 Consolas, "Courier New", monospace; background: #f4f4f4;
      padding: 3px 6px; margin: 3px 0; white-space: pre; }
code { font: 8pt Consolas, "Courier New", monospace; }
table { border-collapse: collapse; margin: 3px 0; }
td, th { border: 1px solid #ccc; padding: 0 5px; text-align: left; }
blockquote { margin: 4px 0; padding: 2px 8px; border-left: 3px solid #d33;
             background: #fff3f3; }
"""


def inline(text):
    text = html.escape(text, quote=False)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<![\w*])\*([^*]+)\*(?!\w)", r"<i>\1</i>", text)
    return text


def convert(md):
    out, lines, i = [], md.splitlines(), 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            j = i + 1
            while not lines[j].startswith("```"):
                j += 1
            out.append("<pre>%s</pre>" % html.escape("\n".join(lines[i + 1:j])))
            i = j + 1
        elif line.startswith("#"):
            level = len(line) - len(line.lstrip("#"))
            out.append("<h%d>%s</h%d>" % (level, inline(line[level:].strip()), level))
            i += 1
        elif line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r"-+", c) for c in cells):
                    rows.append(cells)
                i += 1
            out.append("<table>" + "".join(
                "<tr>%s</tr>" % "".join("<%s>%s</%s>" % (t, inline(c), t) for c in r)
                for r, t in zip(rows, ["th"] + ["td"] * len(rows))) + "</table>")
        elif line.startswith("- "):
            items = []
            while i < len(lines) and (lines[i].startswith("- ") or
                                      lines[i].startswith("  ")):
                if lines[i].startswith("- "):
                    items.append(lines[i][2:])
                else:
                    items[-1] += " " + lines[i].strip()
                i += 1
            out.append("<ul>%s</ul>" % "".join("<li>%s</li>" % inline(t) for t in items))
        elif line.startswith(">"):
            quote = []
            while i < len(lines) and lines[i].startswith(">"):
                quote.append(lines[i].lstrip("> "))
                i += 1
            out.append("<blockquote>%s</blockquote>" % inline(" ".join(quote)))
        elif line.strip():
            para = []
            while i < len(lines) and lines[i].strip() and not re.match(
                    r"(#|```|\||- |>)", lines[i]):
                para.append(lines[i])
                i += 1
            out.append("<p>%s</p>" % inline(" ".join(para)))
        else:
            i += 1
    return "\n".join(out)


def find_browser():
    candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ]
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome"):
        path = shutil.which(name)
        if path:
            candidates.insert(0, path)
    return next((c for c in candidates if os.path.exists(c)), None)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "SPEC.md")
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "SPEC.pdf")
    with open(src, encoding="utf-8") as f:
        body = convert(f.read())
    page = ("<!doctype html><html><head><meta charset='utf-8'><title>BHTP/1</title>"
            "<style>%s</style></head><body>%s</body></html>" % (CSS, body))
    browser = find_browser()
    if not browser:
        sys.exit("make_pdf: no Chrome/Edge/Chromium found")
    tmp = tempfile.mkdtemp()
    try:
        page_path = os.path.join(tmp, "spec.html")
        with open(page_path, "w", encoding="utf-8") as f:
            f.write(page)
        subprocess.run([browser, "--headless", "--disable-gpu",
                        "--no-pdf-header-footer", "--user-data-dir=" + tmp,
                        "--print-to-pdf=" + os.path.abspath(dst),
                        "file:///" + page_path.replace("\\", "/")],
                       check=True, timeout=120,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    with open(dst, "rb") as f:
        pages = len(re.findall(rb"/Type\s*/Page[^s]", f.read()))
    print("wrote %s (%d pages)" % (dst, pages))


if __name__ == "__main__":
    main()
