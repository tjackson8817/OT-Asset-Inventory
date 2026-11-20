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

# Add your own vendor (MAC OUI) entries on top of the bundled IEEE database
python3 ot_asset_inventory.py --pcap capture.pcap --oui-db my_extra_ouis.json

# Refresh the bundled vendor database from the IEEE registry
python3 update_oui_db.py
```

Produces `<out-prefix>.csv` (primary spreadsheet output, one row per asset),
`.json`, `.md`, and `.pdf` (if `reportlab` is installed). When they apply, it
also writes `<out-prefix>_external.csv` (internet addresses internal hosts
talked to) and `<out-prefix>_layer2.csv` (layer-2 devices that could not be
matched to a known device). The output folder is created if it doesn't exist.

## How role classification works

- **Converged IT/OT Host** — hosts an OT service (open OT port, or receives
  OT traffic) and also runs Windows/IT host services (RDP, SMB, RPC, NetBIOS,
  VNC) or is identified as Windows: typically historians and engineering
  workstations running OT software
- **Likely PLC / RTU / Field Device** — has an OT protocol port open, or is
  the *destination* of OT protocol traffic without initiating it. A web,
  Telnet, FTP, SSH or SNMP service on its own does **not** make a device IT
  (most PLCs, RTUs and gateways run one); those are flagged in Notes instead
- **Likely Engineering Workstation / HMI** — initiates OT protocol traffic
  to other devices without hosting an OT service itself
- **IT-only Asset** — open ports, but no OT protocol involvement observed
- **Unclassified / Insufficient Data** — not enough signal either way

This is a heuristic starting point for building a real asset inventory, not
a certified device-identity determination -- verify against your own
records, especially before using it to justify a network change.

## Notes column: what to look at

Each asset gets notes for things an assessor should check, and the
Markdown/PDF list them under **Assets to Look At**, most important first:
- **Sends OT protocol traffic from outside the OT subnet(s)**: e.g. an
  IT-network laptop writing Modbus to a PLC
- **Talks to internet address(es)**: the addresses and ports it contacted
- **Cleartext management service(s) open**: Telnet, FTP, HTTP or SNMP
- **Seen only through a router**: its own MAC/vendor isn't in the capture

Broadcast, multicast and internet addresses are not counted as assets.
Internet addresses go to `<out-prefix>_external.csv` and an "Internet
Connections" section instead.

## Vendor identification (MAC OUI lookup)

`oui_vendors.json` is built from the official IEEE MAC address registry
(35,084 vendor prefixes), so vendors are identified from a capture alone.
Refresh it with `python3 update_oui_db.py`. It downloads
https://standards-oui.ieee.org/oui/oui.txt; if that's blocked, save the file
in a browser and run `python3 update_oui_db.py --file oui.txt`. Add your own
entries with `--oui-db your_file.json` (same `{"XX:XX:XX": "Vendor Name"}`
format).

If Nmap reports a MAC vendor for a host, the tool uses it when the registry
has no match. A MAC that carries several IP addresses is treated as a
router and is not attributed to the hosts behind it.

## Layer-2-only devices

Protocols like PROFINET, EtherCAT, and IEC 61850 GOOSE/Sampled Values often
run directly over Ethernet with no IP address at all. When the MAC
belongs to a device already in the inventory, those protocols are added to
that device. MACs that can't be matched are listed separately: in
`<out-prefix>_layer2.csv`, their own Markdown/PDF section, and their own
array in the JSON.

## Limitations

- Role classification is heuristic, based only on what's visible in the
  capture/scan you provide -- a device that didn't communicate during your
  capture window won't show the traffic-direction signal that informs its
  role.
- Vendor identification needs the device's own MAC address, which only
  appears in a capture taken on the device's own subnet; hosts seen through
  a router show "Unknown."
- Like the Risk Analyzer, this performs best-effort protocol/port
  recognition -- it is not a certified asset-discovery platform.
