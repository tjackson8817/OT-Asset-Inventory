#!/usr/bin/env python3
"""
update_oui_db.py -- rebuild oui_vendors.json (MAC prefix -> vendor) from the official IEEE registry.

Usage (run in the same folder as ot_asset_inventory.py):
    python update_oui_db.py                 # downloads https://standards-oui.ieee.org/oui/oui.txt
    python update_oui_db.py --file oui.txt  # or use a copy of oui.txt you downloaded yourself

If the IEEE site blocks the download, open https://standards-oui.ieee.org/oui/oui.txt in a browser,
save it as oui.txt next to this script, and use --file. As a last resort, `pip install netaddr`
ships a copy of the registry; this script uses it automatically when no other source works.
"""
import argparse
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path

IEEE_URL = "https://standards-oui.ieee.org/oui/oui.txt"
LINE = re.compile(r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$")


def parse(text):
    db = {}
    for line in text.splitlines():
        m = LINE.match(line)
        if m:
            vendor = m.group(4).strip().rstrip(",").strip()
            db[":".join(g.upper() for g in m.groups()[:3])] = vendor
    return db


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", help="Path to a downloaded IEEE oui.txt")
    ap.add_argument("--out", default=str(Path(__file__).parent / "oui_vendors.json"))
    args = ap.parse_args()

    text, source = None, None
    if args.file:
        text, source = Path(args.file).read_text(encoding="utf-8", errors="replace"), f"IEEE oui.txt ({args.file})"
    else:
        try:
            req = urllib.request.Request(IEEE_URL, headers={"User-Agent": "Mozilla/5.0 (oui-db-updater)"})
            text, source = urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace"), IEEE_URL
        except Exception as e:
            print(f"[!] Download failed ({e}); trying the copy bundled with netaddr", file=sys.stderr)
            try:
                import netaddr
                p = Path(netaddr.__file__).parent / "eui" / "oui.txt"
                text, source = p.read_text(encoding="utf-8", errors="replace"), f"IEEE registry bundled with netaddr {netaddr.__version__}"
            except Exception:
                sys.exit("No source available. Download oui.txt in a browser and rerun with --file oui.txt")

    db = parse(text)
    if len(db) < 1000:
        sys.exit(f"Only {len(db)} entries parsed; is that really the IEEE oui.txt file?")
    out = {"_comment": f"MAC address prefix (OUI) -> vendor, from the IEEE MA-L registry. Source: {source}. "
                       f"Built {date.today().isoformat()} by update_oui_db.py. {len(db)} entries."}
    out.update(dict(sorted(db.items())))
    Path(args.out).write_text(json.dumps(out, indent=0, ensure_ascii=False), encoding="utf-8")
    print(f"[*] Wrote {args.out}: {len(db)} vendor prefixes")


if __name__ == "__main__":
    main()
