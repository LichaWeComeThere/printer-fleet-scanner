"""Render samples/fleet_log.txt as a fake PowerShell console PNG for the README.

Run from the repo root:  python docs/render_console.py
Output: docs/demo-console.png
"""
import os
from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "samples", "fleet_log.txt")
OUT = os.path.join(ROOT, "docs", "demo-console.png")

COLORS = {
    "START": (86, 182, 194), "LOCAL": (86, 182, 194), "PLAN": (86, 182, 194), "FILES": (86, 182, 194),
    "PASS": (86, 182, 194), "NEW": (120, 220, 120), "MOVED": (86, 182, 194), "GONE": (229, 192, 70),
    "BACK": (120, 220, 120), "CHECK": (140, 140, 140), "NETWORK": (240, 90, 90),
}
BG = (12, 12, 12)
FG = (204, 204, 204)
BANNER = (86, 182, 194)


def pick_font(size):
    for p in ["/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
              "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
              "C:/Windows/Fonts/consola.ttf"]:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def main():
    font = pick_font(15)
    lines = ["", "=============== PRINTER FLEET SCAN ===============", ""]
    with open(LOG, encoding="utf-8") as f:
        lines += [l.rstrip("\n") for l in f]
    width_chars = 150
    lines = [l[:width_chars] for l in lines]
    cw, ch = font.getbbox("M")[2], 20
    pad = 14
    img = Image.new("RGB", (cw * width_chars + pad * 2, ch * (len(lines) + 1) + pad * 2 + 28), BG)
    d = ImageDraw.Draw(img)
    # title bar
    d.rectangle([0, 0, img.width, 28], fill=(32, 32, 32))
    d.text((12, 6), "Windows PowerShell", font=font, fill=FG)
    y = 28 + pad
    for l in lines:
        color = FG
        if l.startswith("====="):
            color = BANNER
        else:
            parts = l.split()
            if len(parts) >= 3 and parts[2] in COLORS:
                color = COLORS[parts[2]]
        d.text((pad, y), l, font=font, fill=color)
        y += ch
    # progress line
    d.text((pad, y), "Printer fleet scan - pass 7   192.168.41.0/24 ... (8% of pass) | printers known: 24 | new this pass: 7 | moved: 1 | elapsed 172 min",
           font=font, fill=(255, 255, 255))
    img.save(OUT, optimize=True)
    print(OUT, img.size)


if __name__ == "__main__":
    main()
