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
import ipaddress
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
# Services that make a host look like a Windows/IT server or workstation.
HOST_IT_PORTS = {135, 139, 445, 3389, 5900}
# Management services that PLCs, RTUs, gateways and switches commonly run themselves.
# They are worth flagging (cleartext management), but they do not make a field device "IT".
EMBEDDED_MGMT_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 161: "SNMP"}
CLEARTEXT_MGMT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 161: "SNMP"}

ETHERTYPE_PROTOCOLS = {
    0x8892: "PROFINET", 0x88A4: "EtherCAT", 0x88B8: "IEC 61850 GOOSE",
    0x88BA: "IEC 61850 Sampled Values", 0x88F7: "PTP (L2)",
}

DEFAULT_OUI_DB_PATH = Path(__file__).parent / "oui_vendors.json"

# Ports that identify the *service* side of a conversation (used to tell which end is the server)
SERVICE_PORTS = set(range(1, 1024)) | {1433, 1521, 3306, 3389, 5432, 5900, 5938, 7070, 8080, 8443, 8530, 9443, 49320}


def service_port(sport, dport):
    """Return (port, server_is_dst) for a TCP/UDP conversation: the well-known/listening port and
    which side owns it. Falls back to the lower port when neither side is obviously a service."""
    if sport is None or dport is None:
        return dport if dport is not None else sport, True
    known_d = dport in OT_PORTS or dport in SERVICE_PORTS or dport in IT_RISK_PORTS
    known_s = sport in OT_PORTS or sport in SERVICE_PORTS or sport in IT_RISK_PORTS
    if known_d and not known_s:
        return dport, True
    if known_s and not known_d:
        return sport, False
    return (dport, True) if dport <= sport else (sport, False)


def ip_kind(ip):
    """'internal', 'external', or 'skip' (broadcast, multicast, unspecified, invalid)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "skip"
    if a.is_multicast or a.is_unspecified or a.is_reserved or str(a) == "255.255.255.255":
        return "skip"
    if a.is_loopback or a.is_link_local:
        return "skip"
    return "internal" if a.is_private else "external"


def subnet24(ip):
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return None


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
        self.external_peers = set()  # internet addresses this device talked to
        self.routed = False          # only seen through a router, so its own MAC is unknown

    def touch(self, ts):
        if ts is None:
            return
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts


BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def is_group_mac(mac):
    # multicast/broadcast MACs have the least-significant bit of the first octet set
    try:
        return bool(int(mac.split(":")[0], 16) & 1)
    except (ValueError, AttributeError, IndexError):
        return False


def analyze_pcap(path):
    devices = defaultdict(DeviceRecord)   # keyed by internal IP
    l2_only = defaultdict(DeviceRecord)   # keyed by MAC, for non-IP ethertype protocols
    external = defaultdict(lambda: {"internal_peers": set(), "ports": set(), "packets": 0,
                                    "inbound": set(), "outbound": set()})
    mac_ips = defaultdict(set)            # MAC -> internal IPs it carried (more than one = router)
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

        kinds = {src: ip_kind(src), dst: ip_kind(dst)}
        # a subnet broadcast (e.g. 10.10.20.255) shows up with a broadcast destination MAC
        if dst_mac and is_group_mac(dst_mac):
            kinds[dst] = "skip"

        for ip, mac in ((src, src_mac), (dst, dst_mac)):
            if mac and not is_group_mac(mac) and kinds[ip] != "skip":
                mac_ips[mac.lower()].add(ip)   # internet IPs count too: they reveal the router MAC
            if kinds[ip] != "internal":
                continue
            rec = devices[ip]
            if mac and not is_group_mac(mac):
                rec.macs.add(mac)
            rec.packet_count += 1
            rec.touch(ts)

        # remember internet-facing conversations instead of listing internet hosts as assets
        for ext_ip, int_ip in ((dst, src), (src, dst)):
            if kinds.get(ext_ip) == "external" and kinds.get(int_ip) == "internal":
                port, server_is_dst = service_port(sport, dport)
                server = dst if server_is_dst else src
                inbound = server == int_ip          # the internet host connected *to* our device
                e = external[ext_ip]
                e["internal_peers"].add(int_ip)
                if port is not None:
                    e["ports"].add(port)
                    (e["inbound"] if inbound else e["outbound"]).add(f"{int_ip}:{port}")
                e["packets"] += 1
                if port is None:
                    devices[int_ip].external_peers.add(ext_ip)
                elif inbound:
                    devices[int_ip].external_peers.add(f"{ext_ip} -> this host's port {port} (inbound)")
                else:
                    devices[int_ip].external_peers.add(f"{ext_ip}:{port}")

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
            if kinds.get(server_ip) != "internal" or kinds.get(client_ip) != "internal":
                continue  # discovery broadcasts and internet traffic don't define OT roles
            devices[server_ip].protocols[proto_name] += 1
            devices[server_ip].ot_dest_count += 1
            devices[server_ip].peers.add(client_ip)
            devices[client_ip].protocols[proto_name] += 1
            devices[client_ip].ot_src_count += 1
            devices[client_ip].peers.add(server_ip)

    # A MAC that carried several IPs is a router/firewall interface, not the hosts behind it.
    router_macs = {m for m, ips in mac_ips.items() if len(ips) > 1}
    for ip, rec in devices.items():
        rec.macs = {m for m in rec.macs if m.lower() not in router_macs}
        if any(m.lower() in router_macs for m in mac_ips if ip in mac_ips[m]):
            rec.routed = True
    return devices, l2_only, dict(external)


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

def classify_role(ot_ports_open, host_it_ports_open, any_ports_open, ot_dest_count, ot_src_count, os_guess=None):
    """Best-guess role. HTTP/HTTPS/SNMP/Telnet/FTP/SSH alone do NOT make a device "IT":
    PLCs, RTUs and protocol gateways commonly run those management services themselves."""
    windows = bool(os_guess) and "windows" in os_guess.lower()
    it_host = host_it_ports_open or windows
    serves_ot = ot_ports_open or ot_dest_count > 0
    if serves_ot and it_host:
        return "Converged IT/OT Host"
    if ot_src_count > 0 and ot_dest_count == 0 and not ot_ports_open:
        return "Likely Engineering Workstation / HMI"
    if ot_src_count > 0 and serves_ot:
        return "Likely Engineering Workstation / HMI (also responds to OT traffic)"
    if serves_ot:
        return "Likely PLC / RTU / Field Device"
    if it_host or any_ports_open:
        return "IT-only Asset"
    return "Unclassified / Insufficient Data"


# ---------------------------------------------------------------------------
# Build the merged inventory
# ---------------------------------------------------------------------------

def build_inventory(pcap_devices, l2_only_devices, nmap_hosts, oui_db, external=None):
    inventory = {}
    external = external or {}

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
            "external_peers": sorted(rec.external_peers),
            "routed": rec.routed,
        }

    for host in nmap_hosts:
        ip = host["ip"]
        if ip is None or ip_kind(ip) == "skip":
            continue
        entry = inventory.setdefault(ip, {
            "ip": ip, "mac": host.get("mac"), "all_macs_seen": [mac for mac in [host.get("mac")] if mac],
            "vendor": None, "os_guess": None, "nmap_mac_vendor": None, "open_ports": [],
            "protocols_observed": [], "protocol_packet_counts": {}, "packet_count": 0,
            "first_seen": None, "last_seen": None, "distinct_peers": 0,
            "ot_dest_count": 0, "ot_src_count": 0, "external_peers": [], "routed": False,
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

    # Layer-2 frames (GOOSE, PROFINET...) from a MAC that belongs to a known device are that device's
    mac_to_ip = {}
    for ip, entry in inventory.items():
        for m in entry["all_macs_seen"]:
            mac_to_ip[m.lower()] = ip
    unmatched_l2 = {}
    for mac, rec in l2_only_devices.items():
        ip = mac_to_ip.get(mac.lower())
        if ip:
            e = inventory[ip]
            for proto, n in rec.protocols.items():
                e["protocol_packet_counts"][proto] = e["protocol_packet_counts"].get(proto, 0) + n
            e["protocols_observed"] = sorted(set(e["protocols_observed"]) | set(rec.protocols))
        else:
            unmatched_l2[mac] = rec

    rows = []
    for ip, entry in inventory.items():
        ports = {p["port"] for p in entry["open_ports"]}
        ot_ports_open = bool(ports & set(OT_PORTS))
        host_it_ports_open = bool(ports & HOST_IT_PORTS)
        role = classify_role(ot_ports_open, host_it_ports_open, bool(ports), entry["ot_dest_count"],
                             entry["ot_src_count"], entry.get("os_guess"))
        entry["role"] = role
        entry["open_ports_display"] = ", ".join(
            f"{p['port']}/{p['service'] or '?'}" for p in entry["open_ports"]
        ) or None
        rows.append(entry)

    # Notes: things an assessor should look at, per asset
    ot_subnets = {subnet24(r["ip"]) for r in rows if r["role"].startswith("Likely PLC")}
    nmap_ips = {h["ip"] for h in nmap_hosts if h.get("ip")}
    scanned_subnets = {subnet24(ip) for ip in nmap_ips}
    for r in rows:
        notes = []
        if nmap_ips and r["ip"] not in nmap_ips and r["packet_count"] > 0:
            ot = [p for p in r["protocols_observed"] if p not in ETHERTYPE_PROTOCOLS.values()]
            if subnet24(r["ip"]) in scanned_subnets:
                notes.append("Seen in traffic but did not answer the Nmap scan of its subnet: unmanaged, "
                             "transient or rogue device?" + (f" Speaks {', '.join(ot)}." if ot else ""))
            else:
                notes.append("Seen in traffic, on a subnet the Nmap scan did not cover")
        if r["ot_src_count"] > 0 and ot_subnets and subnet24(r["ip"]) not in ot_subnets:
            notes.append("Sends OT protocol traffic from outside the OT subnet(s)")
        if r.get("external_peers"):
            inb = [x for x in r["external_peers"] if x.endswith("(inbound)")]
            outb = [x for x in r["external_peers"] if not x.endswith("(inbound)")]
            if inb:
                notes.append("Accepts connections from the internet: " + ", ".join(inb[:4]) + (" ..." if len(inb) > 4 else ""))
            if outb:
                notes.append("Talks to internet address(es): " + ", ".join(outb[:4]) + (" ..." if len(outb) > 4 else ""))
        clear = sorted(CLEARTEXT_MGMT_PORTS[p["port"]] for p in r["open_ports"] if p["port"] in CLEARTEXT_MGMT_PORTS)
        if clear and not r["role"].startswith("IT-only"):
            notes.append("Cleartext management service(s) open: " + ", ".join(clear))
        if r.get("routed") and not r.get("mac"):
            notes.append("Seen only through a router, so its own MAC/vendor is not visible in this capture")
        r["notes"] = notes

    # L2-only (no-IP) devices that could not be matched to a known device
    l2_rows = []
    for mac, rec in unmatched_l2.items():
        l2_rows.append({
            "mac": mac,
            "vendor": vendor_lookup(mac, oui_db),
            "protocols_observed": sorted(rec.protocols.keys()),
            "packet_count": rec.packet_count,
            "first_seen": iso_from_epoch(rec.first_seen),
            "last_seen": iso_from_epoch(rec.last_seen),
        })

    def ip_sort(ip):
        try:
            return ipaddress.ip_address(ip)
        except ValueError:
            return ipaddress.ip_address("0.0.0.0")
    role_order = ["Converged IT/OT Host", "Likely PLC / RTU / Field Device"]
    rows.sort(key=lambda r: (role_order.index(r["role"]) if r["role"] in role_order else 9, ip_sort(r["ip"])))

    ext_rows = [{"external_ip": ip, "internal_peers": sorted(e["internal_peers"]),
                 "ports": sorted(e["ports"]), "packets": e["packets"],
                 "direction": ("Inbound" if e["inbound"] and not e["outbound"] else
                               "Both" if e["inbound"] else "Outbound"),
                 "inbound_to": sorted(e["inbound"]), "outbound_to": sorted(e["outbound"])}
                for ip, e in sorted(external.items())]
    return rows, l2_rows, ext_rows


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

def flagged_by_priority(rows):
    """Assets with notes, most important first: devices the internet connects into and unscanned
    devices speaking OT protocols, then other unscanned devices and OT traffic from outside the OT
    subnet, then internet contact, then cleartext management services."""
    def rank(r):
        text = " ".join(r.get("notes", []))
        if "Accepts connections from the internet" in text or ("did not answer the Nmap scan" in text and "Speaks" in text):
            tier = 0
        elif "did not answer the Nmap scan" in text or "outside the OT subnet" in text:
            tier = 1
        elif "internet" in text:
            tier = 2
        else:
            tier = 3
        return (tier, -len(r.get("notes", [])))
    return sorted((r for r in rows if r.get("notes")), key=rank)


def render_csv(rows, l2_rows, path, ext_rows=None):
    """Main CSV holds one table only (sortable/filterable in Excel). Layer-2-only devices and
    internet connections go to their own <prefix>_layer2.csv / <prefix>_external.csv files."""
    written = [path]
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow([
            "IP", "MAC", "Vendor", "Role", "Notes", "OS Guess", "Open Ports", "Protocols Observed",
            "Packet Count", "Distinct Peers", "First Seen", "Last Seen"
        ])
        for r in rows:
            writer.writerow([
                r["ip"], r["mac"] or "", r["vendor"] or "Unknown", r["role"], "; ".join(r.get("notes", [])),
                r["os_guess"] or "", r["open_ports_display"] or "", "; ".join(r["protocols_observed"]),
                r["packet_count"], r["distinct_peers"], r["first_seen"] or "", r["last_seen"] or "",
            ])
    base = path[:-4] if path.lower().endswith(".csv") else path
    if l2_rows:
        l2_path = base + "_layer2.csv"
        with open(l2_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["MAC", "Vendor", "Protocols Observed", "Packet Count", "First Seen", "Last Seen"])
            for r in l2_rows:
                writer.writerow([r["mac"], r["vendor"] or "Unknown", "; ".join(r["protocols_observed"]),
                                 r["packet_count"], r["first_seen"] or "", r["last_seen"] or ""])
        written.append(l2_path)
    if ext_rows:
        ext_path = base + "_external.csv"
        with open(ext_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["Internet Address", "Direction", "Internal Host(s)", "Service Port(s)", "Packets",
                             "Inbound (internal host:port reached from the internet)", "Outbound (internal host:remote port)"])
            for e in ext_rows:
                writer.writerow([e["external_ip"], e.get("direction", ""), "; ".join(e["internal_peers"]),
                                 ", ".join(str(p) for p in e["ports"]), e["packets"],
                                 "; ".join(e.get("inbound_to", [])), "; ".join(e.get("outbound_to", []))])
        written.append(ext_path)
    return written


def render_json(rows, l2_rows, pcap_path, nmap_path, ext_rows=None):
    out = {
        "generated": now_iso(),
        "inputs": {"pcap": pcap_path, "nmap_xml": nmap_path},
        "asset_count": len(rows),
        "by_role": dict(Counter(r["role"] for r in rows)),
        "assets": rows,
        "layer2_only_devices": l2_rows,
        "internet_connections": ext_rows or [],
    }
    return json.dumps(out, indent=2, default=str)


def render_markdown(rows, l2_rows, pcap_path, nmap_path, ext_rows=None):
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

    flagged = flagged_by_priority(rows)
    if flagged:
        lines.append("## Assets to Look At")
        lines.append("")
        for r in flagged:
            lines.append(f"- **{r['ip']}** ({r['role']}): " + "; ".join(r["notes"]))
        lines.append("")

    lines.append("## Asset Table")
    lines.append("")
    lines.append("| IP | MAC | Vendor | Role | Open Ports | Protocols | Notes |")
    lines.append("|----|-----|--------|------|------------|-----------|-------|")
    for r in rows:
        lines.append(
            f"| {r['ip']} | {r['mac'] or '--'} | {r['vendor'] or 'Unknown'} | {r['role']} | "
            f"{r['open_ports_display'] or '--'} | {', '.join(r['protocols_observed']) or '--'} | "
            f"{'; '.join(r.get('notes', [])) or '--'} |"
        )
    lines.append("")

    if ext_rows:
        lines.append("## Internet Connections (Not Assets)")
        lines.append("")
        lines.append("Public IP addresses that internal hosts talked to. They are listed here, not in the asset table.")
        lines.append("")
        lines.append("| Internet Address | Direction | Internal Host(s) | Service Port(s) | Packets |")
        lines.append("|------------------|-----------|------------------|-----------------|---------|")
        for e in ext_rows:
            lines.append(f"| {e['external_ip']} | {e.get('direction', '')} | {', '.join(e['internal_peers'])} | "
                         f"{', '.join(str(p) for p in e['ports']) or '--'} | {e['packets']} |")
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


def render_pdf(rows, l2_rows, pcap_path, nmap_path, path, ext_rows=None):
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

    flagged = flagged_by_priority(rows)
    if flagged:
        story.append(Paragraph("Assets to Look At", styles["Heading2"]))
        for r in flagged:
            story.append(Paragraph(f"<b>{r['ip']}</b> ({r['role']}): " + "; ".join(r["notes"]), styles["SmallBody"]))
            story.append(Spacer(1, 3))
        story.append(Spacer(1, 10))

    story.append(Paragraph("Asset Table", styles["Heading2"]))
    table_data = [["IP", "MAC", "Vendor", "Role", "Open Ports", "Protocols"]]
    for r in rows:
        table_data.append([
            r["ip"] or "", r["mac"] or "--", Paragraph(r["vendor"] or "Unknown", styles["SmallBody"]),
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

    small_table_style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ])
    if ext_rows:
        story += [Spacer(1, 14), Paragraph("Internet Connections (Not Assets)", styles["Heading2"])]
        data = [["Internet Address", "Direction", "Internal Host(s)", "Service Port(s)", "Packets"]] + [
            [e["external_ip"], e.get("direction", ""), Paragraph(", ".join(e["internal_peers"]), styles["SmallBody"]),
             ", ".join(str(p) for p in e["ports"]) or "--", str(e["packets"])] for e in ext_rows]
        t = Table(data, colWidths=[1.4 * inch, 0.9 * inch, 2.3 * inch, 1.3 * inch, 0.8 * inch], repeatRows=1)
        t.setStyle(small_table_style)
        story.append(t)
    if l2_rows:
        story += [Spacer(1, 14), Paragraph("Layer 2 Only Devices (No IP Address Observed)", styles["Heading2"])]
        data = [["MAC", "Vendor", "Protocols", "Packets"]] + [
            [r["mac"], Paragraph(r["vendor"] or "Unknown", styles["SmallBody"]),
             Paragraph(", ".join(r["protocols_observed"]), styles["SmallBody"]), str(r["packet_count"])] for r in l2_rows]
        t = Table(data, colWidths=[1.6 * inch, 2.6 * inch, 1.6 * inch, 0.9 * inch], repeatRows=1)
        t.setStyle(small_table_style)
        story.append(t)

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
    parser.add_argument("--oui-db", help="Path to an additional JSON file of MAC-prefix -> vendor entries to merge with the bundled IEEE database")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF generation even if reportlab is installed")
    args = parser.parse_args()

    if not args.pcap and not args.nmap_xml:
        parser.error("Provide at least one of --pcap or --nmap-xml")

    oui_db = load_oui_db(args.oui_db)

    pcap_devices, l2_only, external = {}, {}, {}
    if args.pcap:
        print(f"[*] Analyzing PCAP: {args.pcap}")
        pcap_devices, l2_only, external = analyze_pcap(args.pcap)
        print(f"    -> {len(pcap_devices)} internal IP device(s), {len(l2_only)} layer-2-only MAC(s), "
              f"{len(external)} internet address(es)")

    nmap_hosts = []
    if args.nmap_xml:
        print(f"[*] Analyzing Nmap XML: {args.nmap_xml}")
        nmap_hosts = analyze_nmap_xml(args.nmap_xml)
        print(f"    -> {len(nmap_hosts)} host(s) parsed")

    rows, l2_rows, ext_rows = build_inventory(pcap_devices, l2_only, nmap_hosts, oui_db, external)

    out_dir = Path(args.out_prefix).parent
    if str(out_dir) not in ("", "."):
        out_dir.mkdir(parents=True, exist_ok=True)

    csv_path = f"{args.out_prefix}.csv"
    json_path = f"{args.out_prefix}.json"
    md_path = f"{args.out_prefix}.md"
    pdf_path = f"{args.out_prefix}.pdf"

    csv_paths = render_csv(rows, l2_rows, csv_path, ext_rows)
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(render_json(rows, l2_rows, args.pcap, args.nmap_xml, ext_rows))
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(rows, l2_rows, args.pcap, args.nmap_xml, ext_rows))

    print(f"[*] Wrote {', '.join(csv_paths)}, {json_path}, {md_path}")

    if not args.no_pdf:
        if HAVE_REPORTLAB:
            render_pdf(rows, l2_rows, args.pcap, args.nmap_xml, pdf_path, ext_rows)
            print(f"[*] Wrote {pdf_path}")
        else:
            print("[*] Skipped PDF -- install with: pip install reportlab --break-system-packages")

    print(f"[*] {len(rows)} assets identified" + (f", {len(l2_rows)} layer-2-only devices" if l2_rows else "")
          + (f", {len(ext_rows)} internet address(es) contacted" if ext_rows else ""))


if __name__ == "__main__":
    main()
