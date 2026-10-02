#!/usr/bin/env python3
"""Generate Khandaq's logo assets from geometry constants.

The mark is a trench earthwork: two nested chevron polylines (ember over steel) with a gold
point above. Edit the constants below and re-run from the repository root:

    python3 docs/assets/genlogo.py            # write the SVGs
    python3 docs/assets/genlogo.py --no-png   # SVGs only (default; PNG step is a stub)

This writes mark.svg, icon.svg, logo-dark.svg, logo-light.svg and social-preview.svg next to this
script. It is intentionally dependency-free; PNG rendering (optional, via headless Chromium) is left
as a stub to wire up when raster fallbacks are needed.
"""
from __future__ import annotations

import argparse
from pathlib import Path

# Geometry on a 0..64 grid. EMBER is the upper chevron (the trench lip), STEEL the lower (the floor),
# DOT the protected point above.
EMBER = "M8 40 L22 26 L32 35 L42 26 L56 40"
STEEL = "M13 49 L24 39 L32 45 L40 39 L51 49"
DOT = (32, 20, 3.6)

# Palettes
DARK = {"ember": "#d97a44", "steel": "#7fa6b8", "gold": "#d9b46b", "text": "#f1ebe3"}
LIGHT = {"ember": "#b5551f", "steel": "#35697e", "gold": "#8a6512", "text": "#1a1512"}
TILE = "#161210"
SERIF = "'Cormorant', 'Iowan Old Style', Georgia, serif"

HERE = Path(__file__).resolve().parent


def _mark(stroke_ember: str, stroke_steel: str, gold: str, sw: float = 3.6) -> str:
    cx, cy, r = DOT
    return (
        '  <g fill="none" stroke-linecap="round" stroke-linejoin="round">\n'
        f'    <path d="{EMBER}" stroke="{stroke_ember}" stroke-width="{sw}"/>\n'
        f'    <path d="{STEEL}" stroke="{stroke_steel}" stroke-width="{sw}"/>\n'
        "  </g>\n"
        f'  <circle cx="{cx}" cy="{cy}" r="{r}" fill="{gold}"/>\n'
    )


def mark_svg() -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64" '
        'role="img" aria-label="Khandaq">\n'
        + _mark(DARK["ember"], DARK["steel"], DARK["gold"])
        + "</svg>\n"
    )


def icon_svg() -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64" '
        'role="img" aria-label="Khandaq">\n'
        f'  <rect width="64" height="64" rx="13" fill="{TILE}"/>\n'
        '  <g fill="none" stroke-linecap="round" stroke-linejoin="round">\n'
        f'    <path d="M12 42 L23 30 L32 37 L41 30 L52 42" stroke="{DARK["ember"]}" stroke-width="3.6"/>\n'
        f'    <path d="M16 49 L25 41 L32 46 L39 41 L48 49" stroke="{DARK["steel"]}" stroke-width="3.6"/>\n'
        "  </g>\n"
        f'  <circle cx="32" cy="23" r="3.4" fill="{DARK["gold"]}"/>\n'
        "</svg>\n"
    )


def wordmark_svg(pal: dict[str, str]) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 72" width="320" height="72" '
        'role="img" aria-label="Khandaq">\n'
        '  <g transform="translate(6,4)">\n'
        + "  " + _mark(pal["ember"], pal["steel"], pal["gold"]).replace("\n", "\n  ").rstrip() + "\n"
        + "  </g>\n"
        f'  <text x="86" y="47" font-family="{SERIF}" font-size="40" font-weight="600" '
        f'letter-spacing="0.5" fill="{pal["text"]}">Khandaq</text>\n'
        "</svg>\n"
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-png", action="store_true", help="skip PNG rendering (default)")
    ap.parse_args()

    (HERE / "mark.svg").write_text(mark_svg())
    (HERE / "icon.svg").write_text(icon_svg())
    (HERE / "logo-dark.svg").write_text(wordmark_svg(DARK))
    (HERE / "logo-light.svg").write_text(wordmark_svg(LIGHT))
    print("wrote mark.svg, icon.svg, logo-dark.svg, logo-light.svg")
    print("note: social-preview.svg is maintained by hand; PNG fallbacks are not generated here yet.")


if __name__ == "__main__":
    main()
