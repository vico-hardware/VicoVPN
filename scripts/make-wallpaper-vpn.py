#!/usr/bin/env python3
"""Nettoie le wallpaper VicoMedia : retire le texte « VicoMedia » incruste.

Methode : masque de pixels (blanc peu sature dans la bande du texte),
inpainting OpenCV (Telea) qui reconstruit le fond (masque + glow vert)
en preservant l'artwork. Le branding « VICO VPN » est porte par le logo
HTML de l'UI (police Orbitron + glow vert), pas par le wallpaper —
reessayer de reproduire la calligraphie d'origine donne un rendu
inferieur (teste).

Usage : python scripts/make-wallpaper-vpn.py
Entree : cmd/ui/assets/vico-wallpaper.jpg (original VicoMedia)
Sortie: ecrase le meme fichier (git garde l'historique)
"""
import os

import cv2
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
IMG = os.path.join(HERE, "..", "cmd", "ui", "assets", "vico-wallpaper.jpg")

# Bande contenant le texte « VicoMedia » (trouvee par OCR + analyse pixels)
BAND_Y0, BAND_Y1 = 470, 770
BAND_X0, BAND_X1 = 280, 1420


def build_mask(im):
    lum = cv2.cvtColor(im, cv2.COLOR_BGR2GRAY).astype(np.int32)
    mx = im.max(axis=2).astype(np.int32)
    mn = im.min(axis=2).astype(np.int32)
    sat = mx - mn
    band = np.zeros(lum.shape, np.uint8)
    band[BAND_Y0:BAND_Y1, BAND_X0:BAND_X1] = 255
    white = ((lum > 135) & (sat < 55)).astype(np.uint8) * 255
    return cv2.bitwise_and(white, band)


def main():
    im = cv2.imread(IMG)
    mask = cv2.dilate(build_mask(im), np.ones((3, 3), np.uint8))
    res = cv2.inpaint(im, mask, 9, cv2.INPAINT_TELEA)
    cv2.imwrite(IMG, res, [cv2.IMWRITE_JPEG_QUALITY, 95])
    print("ok ->", IMG)


if __name__ == "__main__":
    main()
