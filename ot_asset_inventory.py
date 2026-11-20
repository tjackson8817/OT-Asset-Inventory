#!/usr/bin/env python3
"""
ot_asset_inventory.py

Companion tool to ot_risk_analyzer.py. Ingests the same inputs -- a PCAP
(from Wireshark) and/or an Nmap XML scan of an OT/ICS network -- but instead
of producing a risk register, builds a structured ASSET INVENTORY: every
device seen, its likely vendor (via MAC OUI lookup), open ports/services,
protocols observed, and a best-guess role classification (PLC/RTU,
engineering workstation/HMI, converged IT/OT host, IT-only, or
unclassified).

USAGE
-----
    python3 ot_asset_inventory.py --pcap capture.pcap --nmap-xml scan.xml \
        --out-prefix ot_asset_inventory

    # PCAP only
    python3 ot_asset_inventory.py --pcap capture.pcap

    # Nmap only
    python3 ot_asset_inventory.py --nmap-xml scan.xml

    # Extend the built-in OUI (MAC vendor) database with your own entries
    python3 ot_asset_inventory.py --pcap capture.pcap --oui-db my_extra_ouis.json

Produces:
    <out-prefix>.csv    the asset inventory as a spreadsheet (primary output)
    <out-prefix>.json   the same data, machine-readable
    <out-prefix>.md      a readable summary (counts by role/vendor/protocol)
    <out-prefix>.pdf     formatted PDF version (requires reportlab; skipped with a note if absent)

REQUIREMENTS
------------
    pip install scapy --break-system-packages
    pip install reportlab --break-system-packages   # optional: PDF output

NOTES ON SCOPE
--------------
Role classification is a heuristic based on observed traffic direction and
open ports -- it is a best-guess starting point for building a real asset
inventory, not a certified discovery tool. The bundled oui_vendors.json is a
small, manually-verified seed set (a handful of common ICS vendors), NOT a
complete OUI database -- extend it yourself from the official IEEE public
registry (https://standards-oui.ieee.org/oui/oui.txt) for full coverage.
"""

import argparse
import csv
import json
import struct
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    from scapy.all import rdpcap, TCP, UDP, IP, Ether
except ImportError:
    print("ERROR: scapy is required. Install with:\n"
          "    pip install scapy --break-system-packages", file=sys.stderr)
    sys.exit(1)

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    HAVE_REPORTLAB = True
except ImportError:
    HAVE_REPORTLAB = False


OT_PORTS = {
    502: "Modbus/TCP", 20000: "DNP3", 44818: "EtherNet/IP (CIP)", 2222: "EtherNet/IP (CIP I/O)",
    102: "S7comm / ISO-TSAP", 47808: "BACnet/IP", 2404: "IEC 60870-5-104", 4840: "OPC UA",
    1962: "PCWorx", 1911: "Niagara Fox", 4911: "Niagara Fox (TLS)", 789: "Red Lion Crimson v3",
    5094: "HART-IP", 9600: "Omron FINS", 5006: "Mitsubishi MELSOFT/MC", 5007: "Mitsubishi MELSOFT/MC",
    1200: "CoDeSys", 2455: "CoDeSys", 18245: "GE SRTP", 18246: "GE SRTP",
    319: "PTP event", 320: "PTP general",
}
IT_RISK_PORTS = {
    21: "FTP", 23: "Telnet", 80: "HTTP", 135: "MSRPC", 139: "NetBIOS",
    445: "SMB", 3389: "RDP", 5900: "VNC", 161: "SNMP", 22: "SSH", 443: "HTTPS",
}
ETHERTYPE_PROTOCOLS = {
    0x8892: "PROFINET", 0x88A4: "EtherCAT", 0x88B8: "IEC 61850 GOOSE",
    0x88BA: "IEC 61850 Sampled Values", 0x88F7: "PTP (L2)",
}

DEFAULT_OUI_DB_PATH = Path(__file__).parent / "oui_vendors.json"


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_from_epoch(ts):
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def load_oui_db(extra_path=None):
    db = {}
    if DEFAULT_OUI_DB_PATH.exists():
        with open(DEFAULT_OUI_DB_PATH) as f:
            raw = json.load(f)
        db.update({k.upper(): v for k, v in raw.items() if not k.startswith("_")})
    if extra_path:
        with open(extra_path) as f:
            raw = json.load(f)
        db.update({k.upper(): v for k, v in raw.items() if not k.startswith("_")})
    return db


def vendor_lookup(mac, oui_db):
    if not mac:
        return None
    prefix = mac.upper().replace("-", ":")[0:8]
    return oui_db.get(prefix)


# ---------------------------------------------------------------------------
# PCAP analysis -> per-IP (and per-MAC, for L2-only devices) traffic records
# ---------------------------------------------------------------------------

class DeviceRecord:
    def __init__(self):
        self.macs = set()
        self.protocols = Counter()
        self.packet_count = 0
        self.first_seen = None
        self.last_seen = None
        self.ot_dest_count = 0     # times this IP was the destination of OT protocol traffic
        self.ot_src_count = 0      # times this IP originated OT protocol traffic
        self.peers = set()        # other IPs this device communicated with (OT context)

    def touch(self, ts):
        if ts is None:
            return
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts


def analyze_pcap(path):
    devices = defaultdict(DeviceRecord)   # keyed by IP
    l2_only = defaultdict(DeviceRecord)   # keyed by MAC, for non-IP ethertype protocols
    packets = rdpcap(path)

    for pkt in packets:
        ts = float(pkt.time) if hasattr(pkt, "time") else None
        src_mac = pkt[Ether].src if Ether in pkt else None
        dst_mac = pkt[Ether].dst if Ether in pkt else None

        # Non-IP, ethertype-based OT protocols (PROFINET, EtherCAT, GOOSE, SV, PTP-L2)
        if Ether in pkt and pkt[Ether].type in ETHERTYPE_PROTOCOLS and IP not in pkt:
            proto = ETHERTYPE_PROTOCOLS[pkt[Ether].type]
            if src_mac:
                rec = l2_only[src_mac]
                rec.macs.add(src_mac)
                rec.protocols[proto] += 1
                rec.packet_count += 1
                rec.touch(ts)
            continue

        if IP not in pkt:
            continue

        src, dst = pkt[IP].src, pkt[IP].dst
        sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)

        for ip, mac in ((src, src_mac), (dst, dst_mac)):
            rec = devices[ip]
            if mac:
                rec.macs.add(mac)
            rec.packet_count += 1
            rec.touch(ts)

        matched_port = None
        for p in (dport, sport):
            if p in OT_PORTS:
                matched_port = p
                break

        if matched_port is not None:
            proto_name = OT_PORTS[matched_port]
            # whichever side owns matched_port as its listening port is the "destination" role
            server_ip = dst if dport == matched_port else src
            client_ip = src if dport == matched_port else dst
            devices[server_ip].protocols[proto_name] += 1
            devices[server_ip].ot_dest_count += 1
            devices[server_ip].peers.add(client_ip)
            devices[client_ip].protocols[proto_name] += 1
            devices[client_ip].ot_src_count += 1
            devices[client_ip].peers.add(server_ip)

    return devices, l2_only


# ---------------------------------------------------------------------------
# Nmap XML analysis
# ---------------------------------------------------------------------------

def analyze_nmap_xml(path):
    hosts = []
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        print(f"[!] Nmap XML parse error: {e}", file=sys.stderr)
        return hosts

    root = tree.getroot()
    for host in root.findall("host"):
        addr_el = host.find("address")
        ip = None
        mac = None
        mac_vendor_nmap = None
        for a in host.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac = a.get("addr")
                mac_vendor_nmap = a.get("vendor")
        if ip is None and addr_el is not None:
            ip = addr_el.get("addr")

        host_entry = {"ip": ip, "mac": mac, "nmap_mac_vendor": mac_vendor_nmap, "open_ports": [], "os": None}
        os_el = host.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                host_entry["os"] = osmatch.get("name")

        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                portid = int(port_el.get("portid"))
                service_el = port_el.find("service")
                service = service_el.get("name") if service_el is not None else None
                product = service_el.get("product") if service_el is not None else None
                version = service_el.get("version") if service_el is not None else None
                host_entry["open_ports"].append({
                    "port": portid, "service": service, "product": product, "version": version
                })
        hosts.append(host_entry)
    return hosts


# ---------------------------------------------------------------------------
# Role classification
# ---------------------------------------------------------------------------

def classify_role(ot_ports_open, it_ports_open, ot_dest_count, ot_src_count):
    if ot_ports_open and it_ports_open:
        return "Converged IT/OT Host"
    if ot_ports_open:
        return "Likely PLC / RTU / Field Device"
    if ot_dest_count > 0 and ot_src_count == 0:
        return "Likely PLC / RTU / Field Device"
    if ot_src_count > 0 and ot_dest_count == 0:
        return "Likely Engineering Workstation / HMI"
    if ot_src_count > 0 and ot_dest_count > 0:
        return "Likely Engineering Workstation / HMI (also responds to OT traffic)"
    if it_ports_open:
        return "IT-only Asset"
    return "Unclassified / Insufficient Data"


# ---------------------------------------------------------------------------
# Build the merged inventory
# ---------------------------------------------------------------------------

def build_inventory(pcap_devices, l2_only_devices, nmap_hosts, oui_db):
    inventory = {}

    for ip, rec in pcap_devices.items():
        mac = sorted(rec.macs)[0] if rec.macs else None
        inventory[ip] = {
            "ip": ip,
            "mac": mac,
            "all_macs_seen": sorted(rec.macs),
            "vendor": vendor_lookup(mac, oui_db) if mac else None,
            "os_guess": None,
            "nmap_mac_vendor": None,
            "open_ports": [],
            "protocols_observed": sorted(rec.protocols.keys()),
            "protocol_packet_counts": dict(rec.protocols),
            "packet_count": rec.packet_count,
            "first_seen": iso_from_epoch(rec.first_seen),
            "last_seen": iso_from_epoch(rec.last_seen),
            "distinct_peers": len(rec.peers),
            "ot_dest_count": rec.ot_dest_count,
            "ot_src_count": rec.ot_src_count,
        }

    for host in nmap_hosts:
        ip = host["ip"]
        if ip is None:
            continue
        entry = inventory.setdefault(ip, {
            "ip": ip, "mac": host.get("mac"), "all_macs_seen": [mac for mac in [host.get("mac")] if mac],
            "vendor": None, "os_guess": None, "nmap_mac_vendor": None, "open_ports": [],
            "protocols_observed": [], "protocol_packet_counts": {}, "packet_count": 0,
            "first_seen": None, "last_seen": None, "distinct_peers": 0,
            "ot_dest_count": 0, "ot_src_count": 0,
        })
        if not entry.get("mac") and host.get("mac"):
            entry["mac"] = host["mac"]
            if host["mac"] not in entry["all_macs_seen"]:
                entry["all_macs_seen"].append(host["mac"])
        entry["nmap_mac_vendor"] = host.get("nmap_mac_vendor")
        entry["os_guess"] = host.get("os")
        entry["open_ports"] = host["open_ports"]
        if not entry.get("vendor") and entry.get("mac"):
            entry["vendor"] = vendor_lookup(entry["mac"], oui_db)
        if not entry.get("vendor") and host.get("nmap_mac_vendor"):
            entry["vendor"] = host["nmap_mac_vendor"]

    rows = []
    for ip, entry in inventory.items():
        ot_ports_open = any(p["port"] in OT_PORTS for p in entry["open_ports"])
        it_ports_open = any(p["port"] in IT_RISK_PORTS for p in entry["open_ports"])
        role = classify_role(ot_ports_open, it_ports_open, entry["ot_dest_count"], entry["ot_src_count"])
        entry["role"] = role
        entry["open_ports_display"] = ", ".join(
            f"{p['port']}/{p['service'] or '?'}" for p in entry["open_ports"]
        ) or None
        rows.append(entry)

    # L2-only (no-IP) devices, kept in a separate list since they can't be merged by IP
    l2_rows = []
    for mac, rec in l2_only_devices.items():
        l2_rows.append({
            "mac": mac,
            "vendor": vendor_lookup(mac, oui_db),
            "protocols_observed": sorted(rec.protocols.keys()),
            "packet_count": rec.packet_count,
            "first_seen": iso_from_epoch(rec.first_seen),
            "last_seen": iso_from_epoch(rec.last_seen),
        })

    rows.sort(key=lambda r: (r["role"] != "Converged IT/OT Host", r["role"] != "Likely PLC / RTU / Field Device", r["ip"] or ""))
    return rows, l2_rows


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

def render_csv(rows, l2_rows, path):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "IP", "MAC", "Vendor", "Role", "OS Guess", "Open Ports", "Protocols Observed",
            "Packet Count", "Distinct Peers", "First Seen", "Last Seen"
        ])
        for r in rows:
            writer.writerow([
                r["ip"], r["mac"] or "", r["vendor"] or "Unknown", r["role"], r["os_guess"] or "",
                r["open_ports_display"] or "", "; ".join(r["protocols_observed"]),
                r["packet_count"], r["distinct_peers"], r["first_seen"] or "", r["last_seen"] or "",
            ])
        if l2_rows:
            writer.writerow([])
            writer.writerow(["-- Layer 2 only devices (no IP address observed) --"])
            writer.writerow(["MAC", "Vendor", "Protocols Observed", "Packet Count", "First Seen", "Last Seen"])
            for r in l2_rows:
                writer.writerow([
                    r["mac"], r["vendor"] or "Unknown", "; ".join(r["protocols_observed"]),
                    r["packet_count"], r["first_seen"] or "", r["last_seen"] or "",
                ])


def render_json(rows, l2_rows, pcap_path, nmap_path):
    out = {
        "generated": now_iso(),
        "inputs": {"pcap": pcap_path, "nmap_xml": nmap_path},
        "asset_count": len(rows),
        "by_role": dict(Counter(r["role"] for r in rows)),
        "assets": rows,
        "layer2_only_devices": l2_rows,
    }
    return json.dumps(out, indent=2, default=str)


def render_markdown(rows, l2_rows, pcap_path, nmap_path):
    lines = []
    lines.append("# OT Asset Inventory")
    lines.append("")
    lines.append(f"*Generated: {now_iso()}*")
    lines.append("")
    lines.append(f"- PCAP: `{pcap_path}`" if pcap_path else "- PCAP: not provided")
    lines.append(f"- Nmap XML: `{nmap_path}`" if nmap_path else "- Nmap XML: not provided")
    lines.append("")
    lines.append("> Role classification is a heuristic based on observed traffic direction and open "
                  "ports -- treat it as a starting point for your real asset inventory, not a confirmed "
                  "device identity.")
    lines.append("")

    by_role = Counter(r["role"] for r in rows)
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total assets identified: **{len(rows)}**")
    for role, count in by_role.most_common():
        lines.append(f"  - {role}: {count}")
    if l2_rows:
        lines.append(f"  - Layer 2 only devices (no IP seen): {len(l2_rows)}")
    lines.append("")

    vendor_counts = Counter(r["vendor"] for r in rows if r["vendor"])
    if vendor_counts:
        lines.append("## Vendors Identified")
        lines.append("")
        for vendor, count in vendor_counts.most_common():
            lines.append(f"- {vendor}: {count}")
        lines.append("")

    proto_counts = Counter()
    for r in rows:
        for p in r["protocols_observed"]:
            proto_counts[p] += 1
    if proto_counts:
        lines.append("## Protocols Observed Across the Network")
        lines.append("")
        for proto, count in proto_counts.most_common():
            lines.append(f"- {proto}: seen on {count} device(s)")
        lines.append("")

    lines.append("## Asset Table")
    lines.append("")
    lines.append("| IP | MAC | Vendor | Role | Open Ports | Protocols |")
    lines.append("|----|-----|--------|------|------------|-----------|")
    for r in rows:
        lines.append(
            f"| {r['ip']} | {r['mac'] or '--'} | {r['vendor'] or 'Unknown'} | {r['role']} | "
            f"{r['open_ports_display'] or '--'} | {', '.join(r['protocols_observed']) or '--'} |"
        )
    lines.append("")

    if l2_rows:
        lines.append("## Layer 2 Only Devices (No IP Address Observed)")
        lines.append("")
        lines.append("| MAC | Vendor | Protocols |")
        lines.append("|-----|--------|-----------|")
        for r in l2_rows:
            lines.append(f"| {r['mac']} | {r['vendor'] or 'Unknown'} | {', '.join(r['protocols_observed'])} |")
        lines.append("")

    return "\n".join(lines)


def render_pdf(rows, l2_rows, pcap_path, nmap_path, path):
    if not HAVE_REPORTLAB:
        return False
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallBody", parent=styles["Normal"], fontSize=8, leading=10))
    doc = SimpleDocTemplate(path, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch,
                             leftMargin=0.5 * inch, rightMargin=0.5 * inch)
    story = [Paragraph("OT Asset Inventory", styles["Title"]), Paragraph(f"Generated: {now_iso()}", styles["Normal"]),
              Spacer(1, 10)]

    by_role = Counter(r["role"] for r in rows)
    summary_data = [["Role", "Count"]] + [[role, str(c)] for role, c in by_role.most_common()]
    summary_table = Table(summary_data, colWidths=[3.5 * inch, 1 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    table_data = [["IP", "MAC", "Vendor", "Role", "Open Ports", "Protocols"]]
    for r in rows:
        table_data.append([
            r["ip"] or "", r["mac"] or "--", r["vendor"] or "Unknown",
            Paragraph(r["role"], styles["SmallBody"]),
            Paragraph(r["open_ports_display"] or "--", styles["SmallBody"]),
            Paragraph(", ".join(r["protocols_observed"]) or "--", styles["SmallBody"]),
        ])
    asset_table = Table(table_data, colWidths=[0.9 * inch, 1.1 * inch, 1.1 * inch, 1.6 * inch, 1.3 * inch, 1.5 * inch], repeatRows=1)
    asset_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
    ]))
    story.append(asset_table)

    doc.build(story)
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Build an OT/ICS asset inventory from a PCAP and/or Nmap XML scan.")
    parser.add_argument("--pcap", help="Path to a PCAP file (e.g. exported from Wireshark)")
    parser.add_argument("--nmap-xml", help="Path to Nmap XML output (nmap -oX)")
    parser.add_argument("--out-prefix", default="ot_asset_inventory", help="Output file prefix")
    parser.add_argument("--oui-db", help="Path to an additional JSON file of MAC-prefix -> vendor entries to merge with the built-in seed database")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF generation even if reportlab is installed")
    args = parser.parse_args()

    if not args.pcap and not args.nmap_xml:
        parser.error("Provide at least one of --pcap or --nmap-xml")

    oui_db = load_oui_db(args.oui_db)

    pcap_devices, l2_only = {}, {}
    if args.pcap:
        print(f"[*] Analyzing PCAP: {args.pcap}")
        pcap_devices, l2_only = analyze_pcap(args.pcap)
        print(f"    -> {len(pcap_devices)} IP-addressed device(s), {len(l2_only)} layer-2-only device(s)")

    nmap_hosts = []
    if args.nmap_xml:
        print(f"[*] Analyzing Nmap XML: {args.nmap_xml}")
        nmap_hosts = analyze_nmap_xml(args.nmap_xml)
        print(f"    -> {len(nmap_hosts)} host(s) parsed")

    rows, l2_rows = build_inventory(pcap_devices, l2_only, nmap_hosts, oui_db)

    csv_path = f"{args.out_prefix}.csv"
    json_path = f"{args.out_prefix}.json"
    md_path = f"{args.out_prefix}.md"
    pdf_path = f"{args.out_prefix}.pdf"

    render_csv(rows, l2_rows, csv_path)
    with open(json_path, "w") as f:
        f.write(render_json(rows, l2_rows, args.pcap, args.nmap_xml))
    with open(md_path, "w") as f:
        f.write(render_markdown(rows, l2_rows, args.pcap, args.nmap_xml))

    print(f"[*] Wrote {csv_path}, {json_path}, {md_path}")

    if not args.no_pdf:
        if HAVE_REPORTLAB:
            render_pdf(rows, l2_rows, args.pcap, args.nmap_xml, pdf_path)
            print(f"[*] Wrote {pdf_path}")
        else:
            print("[*] Skipped PDF -- install with: pip install reportlab --break-system-packages")

    print(f"[*] {len(rows)} assets identified" + (f", {len(l2_rows)} layer-2-only devices" if l2_rows else ""))


if __name__ == "__main__":
    main()
