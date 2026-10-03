#!/usr/bin/env python3
"""Turns real terminal output (with its colours) into a PNG of a terminal window, for the README and makit.sh.

    some command | scripts/screenshot.py --title "makit shield config check" --out docs/img/config-check.png
    scripts/screenshot.py --title … --out … < output.txt

The text is shown as it was printed — nothing is retyped — with the command on the first line ($ …, --command).
Needs Google Chrome or Chromium (headless) for the picture.
"""
import argparse
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile

COLOURS = {30: "#484f58", 31: "#ff7b72", 32: "#3fb950", 33: "#d29922", 34: "#58a6ff", 35: "#bc8cff", 36: "#39c5cf",
           37: "#b1bac4", 90: "#6e7681", 91: "#ffa198", 92: "#56d364", 93: "#e3b341", 94: "#79c0ff", 95: "#d2a8ff",
           96: "#56d4dd", 97: "#ffffff"}
BACKGROUNDS = {41: "#b62324", 42: "#196c2e", 43: "#9e6a03", 44: "#1f6feb"}
SGR = re.compile(r"\x1b\[([0-9;]*)m")


def xterm256(n):
    """The colour of an xterm 256-colour index."""
    base = ["#000000", "#cd3131", "#0dbc79", "#e5e510", "#2472c8", "#bc3fbc", "#11a8cd", "#e5e5e5",
            "#666666", "#f14c4c", "#23d18b", "#f5f543", "#3b8eea", "#d670d6", "#29b8db", "#ffffff"]
    if n < 16:
        return base[n]
    if n < 232:
        n -= 16
        steps = [0, 95, 135, 175, 215, 255]
        return "#%02x%02x%02x" % (steps[n // 36], steps[(n // 6) % 6], steps[n % 6])
    v = 8 + (n - 232) * 10
    return "#%02x%02x%02x" % (v, v, v)


def ansi_to_html(text):
    out, state, pos = [], {"bold": False, "dim": False, "fg": None, "bg": None}, 0

    def span(s):
        if not s:
            return
        style = []
        if state["fg"]:
            style.append(f"color:{state['fg']}")
        if state["bg"]:
            style.append(f"background:{state['bg']}")
        if state["bold"]:
            style.append("font-weight:700")
        if state["dim"]:
            style.append("opacity:.6")
        esc = html.escape(s)
        out.append(f'<span style="{";".join(style)}">{esc}</span>' if style else esc)

    for m in SGR.finditer(text):
        span(text[pos:m.start()])
        pos = m.end()
        codes = [int(c) for c in m.group(1).split(";") if c] or [0]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c in (38, 48) and i + 2 < len(codes) and codes[i + 1] == 5:  # 256 colours
                state["fg" if c == 38 else "bg"] = xterm256(codes[i + 2])
                i += 3
                continue
            if c in (38, 48) and i + 4 < len(codes) and codes[i + 1] == 2:  # true colour
                state["fg" if c == 38 else "bg"] = "#%02x%02x%02x" % tuple(codes[i + 2:i + 5])
                i += 5
                continue
            if c == 0:
                state.update(bold=False, dim=False, fg=None, bg=None)
            elif c == 1:
                state["bold"] = True
            elif c == 2:
                state["dim"] = True
            elif c == 22:
                state.update(bold=False, dim=False)
            elif c == 39:
                state["fg"] = None
            elif c == 49:
                state["bg"] = None
            elif c in COLOURS:
                state["fg"] = COLOURS[c]
            elif c in BACKGROUNDS:
                state["bg"] = BACKGROUNDS[c]
            elif 40 <= c <= 47 or 100 <= c <= 107:
                state["bg"] = COLOURS.get(c - 10, None)
            i += 1
    span(text[pos:])
    return "".join(out)


PAGE = """<!doctype html><meta charset="utf-8"><style>
body {{ margin: 0; background: #0b1220; padding: 28px; display: inline-block;
  background: radial-gradient(700px 400px at 10% 10%, rgba(31,111,235,.30), transparent 60%), linear-gradient(180deg,#0b1220,#0d1117); }}
.win {{ border-radius: 12px; background: #0d1117; border: 1px solid #30363d; box-shadow: 0 24px 60px rgba(0,0,0,.5); overflow: hidden; width: {width}px; }}
.bar {{ display: flex; align-items: center; gap: 8px; padding: 10px 14px; background: #161b22; border-bottom: 1px solid #21262d;
  font: 13px -apple-system, "Segoe UI", sans-serif; color: #8b949e; }}
.bar i {{ width: 12px; height: 12px; border-radius: 50%; display: inline-block; }}
.bar span {{ margin-left: 10px; }}
pre {{ margin: 0; padding: 16px 18px 18px; color: #e6edf3; font: 13.5px/1.55 "JetBrains Mono", SFMono-Regular, Menlo, Consolas, monospace;
  white-space: pre; }}
.cmd {{ color: #7ee787; }}
</style><div class="win"><div class="bar"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i><i style="background:#28c840"></i><span>{title}</span></div>
<pre>{command}{body}</pre></div>"""


def chrome():
    for c in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "google-chrome", "chromium", "chromium-browser"):
        if os.path.exists(c) or shutil.which(c):
            return c
    sys.exit("Google Chrome or Chromium is needed for the picture")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--title", required=True)
    ap.add_argument("--command", default="")
    ap.add_argument("--out", required=True)
    ap.add_argument("--width", type=int, default=980)
    ap.add_argument("--keep-blank", action="store_true", help="keep trailing blank lines (full-screen programs)")
    a = ap.parse_args()
    text = sys.stdin.read()
    if not a.keep_blank:  # a captured terminal pane ends in empty rows and a bare prompt
        lines_in = text.rstrip("\n").split("\n")
        while lines_in and re.sub(r"\x1b\[[0-9;]*m", "", lines_in[-1]).strip() in ("", "$"):
            lines_in.pop()
        text = "\n".join(lines_in)
    command = f'<span class="cmd">$ </span>{html.escape(a.command)}\n' if a.command else ""
    page = PAGE.format(width=a.width, title=html.escape(a.title), command=command, body=ansi_to_html(text))
    lines = text.count("\n") + 2 + (1 if a.command else 0)
    height = 56 + 70 + int(lines * 21)
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "t.html")
        with open(src, "w") as f:
            f.write(page)
        out = os.path.abspath(a.out)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        subprocess.run([chrome(), "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=2",
                        f"--window-size={a.width + 56},{height}", f"--screenshot={out}", "file://" + src],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(out)


if __name__ == "__main__":
    main()
