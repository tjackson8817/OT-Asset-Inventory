# OT Asset Inventory

Companion tool to `ot_risk_analyzer.py`. Same inputs -- a PCAP and/or an
Nmap XML scan -- but instead of a risk register, this builds a structured
**asset inventory**: every device seen, its likely vendor (via MAC address
lookup), open ports/services, protocols observed, and a best-guess role
(PLC/RTU, engineering workstation/HMI, converged IT/OT host, IT-only, or
unclassified).

## Setup

```bash
pip install scapy --break-system-packages
pip install reportlab --break-system-packages   # optional: PDF output
```

## Usage

```bash
# Both inputs
python3 ot_asset_inventory.py --pcap capture.pcap --nmap-xml scan.xml --out-prefix ot_asset_inventory

# PCAP only
python3 ot_asset_inventory.py --pcap capture.pcap

# Nmap only
python3 ot_asset_inventory.py --nmap-xml scan.xml

# Extend the built-in vendor (MAC OUI) database with your own entries
python3 ot_asset_inventory.py --pcap capture.pcap --oui-db my_extra_ouis.json
```

Produces `<out-prefix>.csv` (primary spreadsheet output), `.json`, `.md`,
and `.pdf` (if `reportlab` is installed).

## How role classification works

- **Converged IT/OT Host** — the device has both an OT protocol port and a
  general IT service (RDP, SSH, SMB, etc.) open per the Nmap scan
- **Likely PLC / RTU / Field Device** — has an OT protocol port open, or is
  consistently the *destination* of OT protocol traffic without ever
  initiating it
- **Likely Engineering Workstation / HMI** — initiates OT protocol traffic
  to other devices without hosting an OT service itself
- **IT-only Asset** — only general IT ports open, no OT protocol
  involvement observed at all
- **Unclassified / Insufficient Data** — not enough signal either way

This is a heuristic starting point for building a real asset inventory, not
a certified device-identity determination -- verify against your own
records, especially before using it to justify a network change.

## Vendor identification (MAC OUI lookup)

The tool ships with `oui_vendors.json`, a small **manually verified** seed
set covering a handful of common ICS vendor MAC prefixes (Rockwell
Automation, Siemens, Schneider Electric). This is intentionally NOT a
complete database -- extend it yourself via `--oui-db your_file.json` (same
`{"XX:XX:XX": "Vendor Name"}` format) using:
- The official IEEE public OUI registry: https://standards-oui.ieee.org/oui/oui.txt
- Or any MAC vendor lookup service, for the specific vendors in your environment

If Nmap already reports a MAC vendor for a host (it sometimes does via its
own vendor fingerprinting), the tool uses that as a fallback when the local
OUI database doesn't have a match.

## Layer-2-only devices

Protocols like PROFINET, EtherCAT, and IEC 61850 GOOSE/Sampled Values often
run directly over Ethernet with no IP address at all. These devices can't
be merged into the main IP-keyed table, so they're listed separately (by
MAC address) in a dedicated section of the CSV/MD and a separate array in
the JSON.

## Limitations

- Role classification is heuristic, based only on what's visible in the
  capture/scan you provide -- a device that didn't communicate during your
  capture window won't show the traffic-direction signal that informs its
  role.
- The vendor database is small by design; treat "Unknown" vendor as "not
  yet looked up," not "not an industrial device."
- Like the Risk Analyzer, this performs best-effort protocol/port
  recognition -- it is not a certified asset-discovery platform.
