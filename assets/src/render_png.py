#!/usr/bin/env python3
"""Convierte los SVG de esta carpeta en PNG (Chromium vía Playwright).
Converts the SVG files in this folder into PNG (Chromium via Playwright).

Uso / Usage:
    python3 build_images.py
    python3 render_png.py [carpeta_png]      # por defecto, ../  (carpeta assets/)

Entrada:  <nombre>.<idioma>.svg   (p. ej. header.en.svg)
Salida:   <carpeta_png>/<idioma>/<nombre>.png   (p. ej. assets/en/header.png)

Requisitos / Requirements: `pip install playwright` + Chromium, y la fuente Inter instalada
para que el resultado coincida con el diseño. La cabecera también se genera como
`social-preview.png` a 1280x640 (tamaño exacto de la «social preview» de GitHub); el resto
se renderiza al doble de resolución para que se vea nítido.
"""
import re
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

SRC = Path(__file__).resolve().parent
OUT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else SRC.parent

with sync_playwright() as p:
    browser = p.chromium.launch()
    for svg in sorted(SRC.glob("*.*.svg")):
        name, lang = svg.name[: -len(".svg")].rsplit(".", 1)
        text = svg.read_text(encoding="utf-8")
        w, h = (int(v) for v in re.search(r'width="(\d+)" height="(\d+)"', text).groups())
        dest = OUT / lang
        dest.mkdir(parents=True, exist_ok=True)
        jobs = [(f"{name}.png", 2)]
        if name == "header":
            jobs.append(("social-preview.png", 1))
        for filename, scale in jobs:
            page = browser.new_page(viewport={"width": w, "height": h}, device_scale_factor=scale)
            page.goto(svg.as_uri())
            page.screenshot(path=str(dest / filename), omit_background=False)
            page.close()
            print("renderizado", dest / filename)
    browser.close()
