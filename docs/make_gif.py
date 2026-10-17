"""Render docs/assets/demo.gif: a terminal typing `loot`, the output appearing, then
the same run after the fixes. Frames are drawn from loot's real output on the demo home.

    python docs/make_gif.py <demo home> <fixed demo home> docs/assets/demo.gif

Needs Pillow and a monospace TTF (Cascadia Mono on Windows; falls back to DejaVu Sans Mono).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from rich.console import Console

from loot.machine import Machine
from loot.output import print_result
from loot.scanners import scan

COLS = 86
FONT_SIZE = 14
LINE_H = 18
PAD_X, PAD_Y, BAR_H = 18, 14, 34
BG, BAR, TEXT = (11, 11, 13), (24, 23, 26), (230, 225, 216)
PALETTE = {
    30: (60, 60, 64), 31: (255, 107, 107), 32: (79, 209, 161), 33: (245, 196, 81), 34: (130, 170, 255), 35: (199, 146, 234), 36: (127, 215, 255), 37: (230, 225, 216),
    90: (124, 120, 115), 91: (255, 130, 130), 92: (110, 230, 180), 93: (250, 210, 110), 94: (150, 185, 255), 95: (215, 170, 245), 96: (160, 225, 255), 97: (245, 242, 236),
}
SGR = re.compile(r"\x1b\[([0-9;]*)m")


def font(bold: bool = False) -> ImageFont.FreeTypeFont:
    for p in ["C:/Windows/Fonts/CascadiaMono.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", "/System/Library/Fonts/Menlo.ttc"]:
        if Path(p).exists():
            f = ImageFont.truetype(p, FONT_SIZE)
            if bold and "Cascadia" in p:
                try:
                    f.set_variation_by_name("Bold")
                except Exception:  # noqa: BLE001
                    pass
            return f
    return ImageFont.load_default()


FONT, FONT_B = font(), font(bold=True)
CHAR_W = FONT.getlength("M")


def ansi_lines(home: Path, show_all: bool) -> list[list[tuple[str, tuple[int, int, int], bool]]]:
    """Run loot and return styled lines: [(text, rgb, bold), ...] per line."""
    console = Console(record=True, width=COLS, color_system="standard", force_terminal=True, file=open(Path(__file__).parent / ".gif-scratch.txt", "w", encoding="utf-8"))
    print_result(console, scan(Machine.fake(home, system="linux")), show_all=show_all)
    raw = console.export_text(styles=True)
    lines = []
    for line in raw.split("\n"):
        segs, color, bold, pos = [], TEXT, False, 0
        for m in SGR.finditer(line):
            if m.start() > pos:
                segs.append((line[pos:m.start()], color, bold))
            for code in (m.group(1) or "0").split(";"):
                c = int(code or 0)
                if c == 0:
                    color, bold = TEXT, False
                elif c == 1:
                    bold = True
                elif c == 2:
                    color = PALETTE[90]
                elif c == 39:
                    color = TEXT
                elif c in PALETTE:
                    color = PALETTE[c]
            pos = m.end()
        if pos < len(line):
            segs.append((line[pos:], color, bold))
        lines.append(segs)
    return lines


def draw_frame(rows: list[list[tuple[str, tuple[int, int, int], bool]]], height_lines: int, title: str) -> Image.Image:
    w = int(PAD_X * 2 + CHAR_W * COLS)
    h = BAR_H + PAD_Y * 2 + LINE_H * height_lines
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, BAR_H], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([14 + i * 20, 11, 26 + i * 20, 23], fill=c)
    d.text((w / 2 - FONT.getlength(title) / 2, 8), title, font=FONT, fill=(150, 146, 140))
    y = BAR_H + PAD_Y
    for segs in rows[-height_lines:] if len(rows) > height_lines else rows:
        x = PAD_X
        for text, color, bold in segs:
            d.text((x, y), text, font=FONT_B if bold else FONT, fill=color)
            x += FONT.getlength(text)
        y += LINE_H
    return img


def prompt_row(cmd: str, cursor: bool) -> list[tuple[str, tuple[int, int, int], bool]]:
    row = [("jdoe@laptop:~$ ", PALETTE[32], False), (cmd, TEXT, False)]
    if cursor:
        row.append(("█", (255, 77, 109), False))
    return row


def scene(rows_out, cmd: str, height: int, title: str, frames: list, durations: list, intro_comment: str | None = None, hold: int = 14, keep_lines: int | None = None) -> None:
    base = []
    if intro_comment:
        base.append([(intro_comment, PALETTE[90], False)])
    # blink, then type
    for cur in (True, False, True):
        frames.append(draw_frame(base + [prompt_row("", cur)], height, title)); durations.append(260)
    for i in range(1, len(cmd) + 1):
        frames.append(draw_frame(base + [prompt_row(cmd[:i], True)], height, title)); durations.append(110)
    frames.append(draw_frame(base + [prompt_row(cmd, False)], height, title)); durations.append(350)
    out = rows_out[:keep_lines] if keep_lines else rows_out
    shown = base + [prompt_row(cmd, False)]
    step = 2
    for i in range(0, len(out), step):
        shown = base + [prompt_row(cmd, False)] + out[: i + step]
        frames.append(draw_frame(shown, height, title)); durations.append(55)
    for _ in range(hold):
        frames.append(draw_frame(shown, height, title)); durations.append(130)


def main() -> None:
    demo, fixed, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    before = ansi_lines(demo, show_all=False)
    after = ansi_lines(fixed, show_all=False)
    # scene 1: panel + "Fix these first" header + first three items
    idx = [i for i, r in enumerate(before) if "Fix these first" in "".join(t for t, _, _ in r)]
    cut = idx[0] + 4 if idx else 12
    count, rows1 = 0, []
    for r in before[cut:]:
        rows1.append(r)
        if "".join(t for t, _, _ in r).strip() == "":
            count += 1
            if count == 3:
                break
    scene1 = before[:cut] + rows1
    # scene 2: panel only, then the first category table
    def text(r): return "".join(t for t, _, _ in r)
    cut2 = next((i for i, r in enumerate(after) if text(r).startswith(("Cloud", "SSH", "Browser"))), 12)
    end2 = next((i for i in range(cut2 + 4, len(after)) if text(after[i]).strip() == ""), cut2 + 10)
    scene2 = after[:end2]  # the whole first category table
    height = max(len(scene1), len(scene2) + 1) + 1
    frames: list[Image.Image] = []
    durations: list[int] = []
    scene(scene1, "loot", height, "loot — what would an infostealer take from this laptop?", frames, durations, hold=18)
    scene(scene2, "loot", height, "loot — the same laptop, after an evening of fixes", frames, durations, intro_comment="# an evening later, after working down the list", hold=22)
    pal = [f.quantize(colors=96, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE) for f in frames]
    pal[0].save(out, save_all=True, append_images=pal[1:], duration=durations, loop=0, optimize=True, disposal=1)
    size = out.stat().st_size
    print(f"wrote {out}: {len(frames)} frames, {frames[0].size[0]}x{frames[0].size[1]}, {size/1024:.0f} KB, {sum(durations)/1000:.1f} s")
    scratch = Path(__file__).parent / ".gif-scratch.txt"
    if scratch.exists():
        scratch.unlink()


if __name__ == "__main__":
    main()
