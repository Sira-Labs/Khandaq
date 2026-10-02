# Logo assets

The mark is a **trench earthwork**: two nested chevron lines (the cross-section of a dug trench — the
*khandaq*), an ember line over a steel line, with a single gold point above them for the place being
defended. Attacker thinking laid down as a line in the service of defence. All files are flat SVG on a
transparent background unless noted.

| File | Use |
|---|---|
| `logo-dark.svg` | Mark + wordmark, light text, for dark backgrounds |
| `logo-light.svg` | Mark + wordmark, ink text, for light backgrounds |
| `mark.svg` | Mark only |
| `icon.svg` | Mark on an ink rounded tile, for favicons and avatars; reads at 16 px |
| `social-preview.svg` | 1280×640 card for the repo's social preview (Settings → General → Social preview) |

Colours: ember `#d97a44` (and `#b5551f` on light), steel `#7fa6b8` (`#35697e` on light), gold `#d9b46b`
(`#8a6512` on light), earth/ink tile `#161210`, paper text `#f1ebe3`, ink text `#1a1512`. The wordmark
uses a Cormorant/serif display stack; outline the text before print.

`genlogo.py` regenerates every SVG from the geometry constants at the top of the script (the `EMBER`,
`STEEL` and `DOT` definitions on a 64-unit grid) and can render PNG fallbacks with headless Chromium
(`--no-png` skips that). Run it from the repository root: `python3 docs/assets/genlogo.py`.
