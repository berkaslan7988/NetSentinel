"""Build the fonts bundled with the dashboard (netsentinel/ui/fonts/).

    python tools/build_fonts.py <folder with the google/fonts sources>

The source folder must contain the files from github.com/google/fonts:

    ofl/instrumentsans/InstrumentSans[wdth,wght].ttf  ->  InstrumentSans.ttf
    ofl/instrumentsans/OFL.txt                         ->  OFL-InstrumentSans.txt
    ofl/ibmplexmono/IBMPlexMono-{Regular,Medium,SemiBold}.ttf
    ofl/ibmplexmono/OFL.txt                            ->  OFL-IBMPlexMono.txt

Instrument Sans (no Reserved Font Name) is cut into static instances and
subset to Latin + Turkish. IBM Plex Mono is shipped unmodified, because
"Plex" is a Reserved Font Name and the OFL forbids renaming-free modified
copies.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

from fontTools import subset
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

OUT = Path(__file__).resolve().parent.parent / "netsentinel" / "ui" / "fonts"

# Basic Latin, Latin-1, Latin Extended-A (Turkish), general punctuation,
# arrows, multiplication and minus signs.
UNICODES = (
    list(range(0x20, 0x7F)) + list(range(0xA0, 0x180))
    + list(range(0x2010, 0x2028)) + list(range(0x2030, 0x203B))
    + [0x2190, 0x2191, 0x2192, 0x2193, 0x2212, 0x2009, 0x202F]
)

# (file stem, family, style, width, weight)
INSTANCES = [
    ("InstrumentSans-Regular", "Instrument Sans", "Regular", 100, 400),
    ("InstrumentSans-Medium", "Instrument Sans", "Medium", 100, 500),
    ("InstrumentSans-SemiBold", "Instrument Sans", "SemiBold", 100, 600),
    ("InstrumentSans-Bold", "Instrument Sans", "Bold", 100, 700),
    ("InstrumentSansCondensed-SemiBold", "Instrument Sans Condensed", "SemiBold", 87.5, 600),
]


def _rename(font: TTFont, family: str, style: str, stem: str) -> None:
    name = font["name"]
    for rec in list(name.names):
        if rec.nameID in (1, 2, 3, 4, 6, 16, 17, 25):
            name.removeNames(nameID=rec.nameID)
    legacy_style = "Regular" if style not in ("Regular", "Bold") else style
    legacy_family = family if style in ("Regular", "Bold") else f"{family} {style}"
    for nid, value in (
        (1, legacy_family), (2, legacy_style), (3, f"NetSentinel;{stem}"),
        (4, f"{family} {style}"), (6, stem), (16, family), (17, style),
    ):
        name.setName(value, nid, 3, 1, 0x409)


def build(src: Path) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    var = src / "InstrumentSans.ttf"
    for stem, family, style, wdth, wght in INSTANCES:
        font = instancer.instantiateVariableFont(
            TTFont(var), {"wdth": wdth, "wght": wght}, updateFontNames=False
        )
        _rename(font, family, style, stem)
        font["OS/2"].usWeightClass = wght
        font["OS/2"].usWidthClass = 5 if wdth == 100 else 4
        opts = subset.Options()
        opts.layout_features = ["*"]
        opts.name_IDs = ["*"]
        opts.name_languages = ["*"]
        opts.notdef_outline = True
        sub = subset.Subsetter(opts)
        sub.populate(unicodes=UNICODES)
        sub.subset(font)
        font.save(OUT / f"{stem}.ttf")
        print("wrote", stem, (OUT / f"{stem}.ttf").stat().st_size // 1024, "KB")
    for weight in ("Regular", "Medium", "SemiBold"):
        shutil.copy2(src / f"IBMPlexMono-{weight}.ttf", OUT / f"IBMPlexMono-{weight}.ttf")
        print("copied IBMPlexMono-" + weight)
    shutil.copy2(src / "OFL-InstrumentSans.txt", OUT / "OFL-InstrumentSans.txt")
    shutil.copy2(src / "OFL-IBMPlexMono.txt", OUT / "OFL-IBMPlexMono.txt")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    build(Path(sys.argv[1]))
