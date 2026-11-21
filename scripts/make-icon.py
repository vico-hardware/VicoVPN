#!/usr/bin/env python3
"""Genere l'icone VicoVPN (styles VicoMedia : sombre + glow vert + accent rouge).

Sortie : cmd/ui/assets/icon.ico (multi-tailles) + icon.png (apercu 256px).
Usage : python scripts/make-icon.py
"""
import math
import os
from PIL import Image, ImageDraw, ImageFilter

S = 256  # canvas
BG_TOP = (15, 17, 21)     # #0f1115
BG_BOT = (23, 26, 33)     # #171a21
GREEN = (61, 220, 132)    # glow vert
GREEN_DK = (16, 185, 129) # #10b981
RED = (255, 85, 102)      # accent Vico
WHITE = (240, 244, 248)


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def vgrad(size, top, bot):
    img = Image.new("RGB", (size, size))
    px = img.load()
    for y in range(size):
        c = lerp(top, bot, y / (size - 1))
        for x in range(size):
            px[x, y] = c
    return img


def shield_points(cx, cy, w, h):
    """Bouclier : bords droits, toit arrondi, pointe en bas."""
    x0, x1 = cx - w / 2, cx + w / 2
    y0, y1 = cy - h / 2, cy + h / 2
    pts = []
    # toit : arc superior entre les epaules
    r = w * 0.30
    for a in range(180, 361, 6):
        rad = math.radians(a)
        pts.append((cx + r * math.cos(rad), cy - h / 2 + r * math.sin(rad) * 0.6))
    # epaules -> flancs -> pointe
    pts += [
        (x1, cy - h * 0.18),
        (x1, cy + h * 0.22),
        (cx, y1),
        (x0, cy + h * 0.22),
        (x0, cy - h * 0.18),
    ]
    return pts


def draw_v(draw, cx, cy, size, color, width):
    """Lettre V en deux barres polygonales."""
    s = size
    # barre gauche : de (cx-s*0.28, cy-s*0.30) a (cx, cy+s*0.26)
    # barre droite : de (cx, cy+s*0.26) a (cx+s*0.28, cy-s*0.30)
    t = width / 2
    left = [
        (cx - s * 0.28 - t * 0.4, cy - s * 0.30),
        (cx - s * 0.28 + t * 0.4, cy - s * 0.30),
        (cx + t, cy + s * 0.26),
        (cx - t, cy + s * 0.26),
    ]
    right = [
        (cx + t, cy + s * 0.26),
        (cx - t, cy + s * 0.26),
        (cx + s * 0.28 + t * 0.4, cy - s * 0.30),
        (cx + s * 0.28 - t * 0.4, cy - s * 0.30),
    ]
    draw.polygon(left, fill=color)
    draw.polygon(right, fill=color)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(here, "..", "cmd", "ui", "assets")
    os.makedirs(out_dir, exist_ok=True)

    img = vgrad(S, BG_TOP, BG_BOT).convert("RGBA")

    # --- glow radial derriere le blason ---
    glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    cx = cy = S / 2
    for i in range(60, 0, -1):
        r = i * 2.1
        a = int(26 * (i / 60) ** 1.6)
        gd.ellipse([cx - r, cy - r * 0.92, cx + r, cy + r * 0.92],
                   fill=GREEN + (a,))
    glow = glow.filter(ImageFilter.GaussianBlur(10))
    img.alpha_composite(glow)

    d = ImageDraw.Draw(img)

    # --- blason : contour vert luminous + remplissage sombre ---
    shield = shield_points(cx, cy - 6, 150, 168)
    d.polygon(shield, fill=(13, 18, 16, 235), outline=GREEN_DK + (255,))
    # liseré externe plus fin, effet verre
    inner = shield_points(cx, cy - 6, 138, 156)
    d.line(inner + [inner[0]], fill=GREEN + (200,), width=2)

    # --- lettre V ---
    draw_v(d, cx, cy - 4, 92, GREEN, 20)

    # --- point accent rouge (signature Vico) en bas du blason ---
    d.ellipse([cx - 7, cy + 62, cx + 7, cy + 76], fill=RED + (255,))

    # --- reflet superieur subtil ---
    hi = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    hd = ImageDraw.Draw(hi)
    hd.rounded_rectangle([52, 40, 204, 110], radius=40,
                         fill=(255, 255, 255, 14))
    hi = hi.filter(ImageFilter.GaussianBlur(18))
    img.alpha_composite(hi)

    # arrondi des coins (masque)
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, S - 1, S - 1], radius=56, fill=255)
    out = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    out.paste(img, (0, 0), mask)

    ico_path = os.path.join(out_dir, "icon.ico")
    png_path = os.path.join(out_dir, "icon.png")
    out.save(png_path)
    out.save(ico_path, format="ICO",
             sizes=[(16, 16), (24, 24), (32, 32), (48, 48),
                    (64, 64), (128, 128), (256, 256)])
    print("ecrit:", ico_path)
    print("ecrit:", png_path)


if __name__ == "__main__":
    main()
