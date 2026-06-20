# Version: 13.0.0
# Date:    2026-06-20
# Notes:   Responsive SVG (viewBox only, width=100%); layer order HA→SCS/CSN→GW→LCS→ES/FDB→STORAGE;
#          tiles centered per role line; one role family per row

from __future__ import annotations
import html as _html_mod
import ipaddress
import json as _json
import math as _math
from models import AuditResult, DiscoveredStorageNode

# ─── Role → display layer ─────────────────────────────────────────────────────
# Order top-to-bottom: HA(0) → SCS/CSN(1) → GW(2) → LCS(3) → ES/FDB(4) → STORAGE(5)
ROLE_LAYERS: dict[str, int] = {
    "HAPROXY":              0,
    "SCS":                  1,
    "CSN_PLATFORM":         1,
    "CONTENT_GATEWAY":      2,
    "LISTING_CACHE":        3,
    "LISTING_CACHE_SERVER": 3,
    "ELASTICSEARCH":        4,
    "FOUNDATION_DB":        4,
    "TELEMETRY":            4,
    "STORAGE_NODE":         5,
    "STORAGE_UI":           5,
    "SWARMFS":              5,
    "CONTENT_UI":           6,
    "UNKNOWN":              7,
}

ROLE_COLORS: dict[str, str] = {
    "HAPROXY":              "#c0392b",
    "CONTENT_GATEWAY":      "#2980b9",
    "SCS":                  "#16a085",
    "STORAGE_UI":           "#1abc9c",
    "CONTENT_UI":           "#27ae60",
    "SWARMFS":              "#2ecc71",
    "LISTING_CACHE":        "#f39c12",
    "LISTING_CACHE_SERVER": "#e67e22",
    "ELASTICSEARCH":        "#8e44ad",
    "CSN_PLATFORM":         "#16a085",
    "TELEMETRY":            "#1a6a8a",
    "FOUNDATION_DB":        "#2c3e50",
    "STORAGE_NODE":         "#4a6fa5",
    "UNKNOWN":              "#7f8c8d",
}

ROLE_SHORT: dict[str, str] = {
    "HAPROXY":              "HA",
    "CONTENT_GATEWAY":      "GW",
    "SCS":                  "SCS",
    "STORAGE_UI":           "WEBUI",
    "CONTENT_UI":           "UI",
    "SWARMFS":              "NFS",
    "LISTING_CACHE":        "LCS",
    "LISTING_CACHE_SERVER": "LCS-SRV",
    "ELASTICSEARCH":        "ES",
    "CSN_PLATFORM":         "CSN",
    "TELEMETRY":            "TELEM",
    "FOUNDATION_DB":        "FDB",
    "STORAGE_NODE":         "STOR",
    "UNKNOWN":              "?",
}

LAYER_LABELS: dict[int, str] = {
    0: "HA — Load Balancer",
    1: "SCS / CSN",
    2: "GW — Content Gateway",
    3: "LCS — Listing Cache",
    4: "ES / FDB — Search & DB",
    5: "Storage",
    6: "UI",
    7: "Unknown",
}

SUBNET_PALETTE = [
    "#3498db", "#27ae60", "#e74c3c", "#f39c12",
    "#9b59b6", "#1abc9c", "#e67e22",
]

# ─── Tile layout ──────────────────────────────────────────────────────────────
NODE_W          = 280
NODE_H          = 160     # +5px vs before to accommodate badges
ROLE_STRIP_W    = 58
LEFT_BTN_W      = 40
BODY_W          = NODE_W - ROLE_STRIP_W
INNER_BODY_W    = BODY_W - LEFT_BTN_W
H_GAP           = 100
SUB_ROW_GAP     = 24
MAX_COLS_PER_ROW = 6
TILE_MARGIN_X   = 15
LABEL_H         = 26
FONT            = "Arial, sans-serif"

# ─── Backbone & wire constants ────────────────────────────────────────────────
BACKBONE_PAD_L   = 130    # left margin for public backbone + wires
BACKBONE_PAD_R   = 130    # right margin for private backbone + wires
BACKBONE_PAD_TOP = 60     # top margin for HAProxy horizontal backbone (if present)
BACKBONE_X_INSET = 28     # backbone line x from SVG edge
BACKBONE_STROKE  = 5
WIRE_STEP        = 8      # center-to-center between stacked wires
WIRE_STROKE      = 1.5
WIRE_ROW_MARGIN  = 14     # extra space above/below wire bundle
MIN_LAYER_GAP    = 28
TILE_V_PAD       = 18

# NIC badge (inside tile)
NIC_BADGE_W      = 56     # badge width
NIC_BADGE_H      = 22     # badge height (2 text lines)
NIC_BADGE_STEP   = 60     # horizontal step between consecutive badges


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _darken(hex_color: str, factor: float = 0.35) -> str:
    try:
        h = hex_color.lstrip("#")
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        return f"#{int(r * factor):02x}{int(g * factor):02x}{int(b * factor):02x}"
    except Exception:
        return "#1e293b"


def _primary_role(r: AuditResult) -> str:
    return r.roles[0].role if r.roles else "UNKNOWN"


def _role_icon_svg(role: str, col: str, cx: int, cy: int, scale: float = 1.0) -> list[str]:
    sw_w = max(1.0, 1.5 * scale)
    sw = f'stroke="{col}" stroke-width="{sw_w:.1f}" stroke-linecap="round" stroke-linejoin="round"'
    def t(dx, dy): return f"{cx + dx*scale:.0f},{cy + dy*scale:.0f}"
    def sc(v): return round(v * scale)

    if role == "HAPROXY":
        return [
            f'<line x1="{t(-8,-4)}" x2="{t(0,0)}" {sw} fill="none"/>',
            f'<line x1="{t(-8,4)}" x2="{t(0,0)}" {sw} fill="none"/>',
            f'<line x1="{t(0,0)}" x2="{t(7,0)}" {sw} fill="none"/>',
            f'<polygon points="{t(5,-2)} {t(8,0)} {t(5,2)}" fill="{col}" stroke="none"/>',
        ]
    elif role == "CONTENT_GATEWAY":
        pts = " ".join(t(dx, dy) for dx, dy in [(0,-8),(7,-4),(7,4),(0,8),(-7,4),(-7,-4)])
        return [
            f'<polygon points="{pts}" fill="{col}" fill-opacity="0.15" {sw}/>',
            f'<line x1="{t(-3,0)}" x2="{t(4,0)}" {sw} fill="none"/>',
            f'<polygon points="{t(2,-2)} {t(5,0)} {t(2,2)}" fill="{col}" stroke="none"/>',
        ]
    elif role == "STORAGE_NODE":
        return [
            f'<ellipse cx="{cx}" cy="{cy - sc(5)}" rx="{sc(8)}" ry="{scale*2.5:.1f}" fill="{col}" fill-opacity="0.25" {sw}/>',
            f'<line x1="{t(-8,-5)}" x2="{t(-8,5)}" {sw} fill="none"/>',
            f'<line x1="{t(8,-5)}" x2="{t(8,5)}" {sw} fill="none"/>',
            f'<ellipse cx="{cx}" cy="{cy + sc(5)}" rx="{sc(8)}" ry="{scale*2.5:.1f}" fill="{col}" fill-opacity="0.4" {sw}/>',
        ]
    elif role == "ELASTICSEARCH":
        return [
            f'<circle cx="{cx - sc(1)}" cy="{cy - sc(1)}" r="{scale*5.5:.1f}" fill="{col}" fill-opacity="0.15" {sw}/>',
            f'<line x1="{t(3,3)}" x2="{t(7,7)}" stroke="{col}" stroke-width="{sw_w*1.3:.1f}" stroke-linecap="round"/>',
        ]
    elif role in ("LISTING_CACHE", "LISTING_CACHE_SERVER"):
        pts = " ".join(t(dx, dy) for dx, dy in [(2,-8),(-3,1),(2,1),(-2,8),(3,-1),(-2,-1)])
        return [f'<polygon points="{pts}" fill="{col}" fill-opacity="0.7" stroke="{col}" stroke-width="{sw_w*0.33:.1f}"/>']
    elif role == "SCS":
        inner, outer = sc(4), sc(7)
        teeth = []
        for angle_deg in [0, 45, 90, 135, 180, 225, 270, 315]:
            a = _math.radians(angle_deg)
            x1 = cx + int(inner * _math.cos(a) + 0.5)
            y1 = cy + int(inner * _math.sin(a) + 0.5)
            x2 = cx + int(outer * _math.cos(a) + 0.5)
            y2 = cy + int(outer * _math.sin(a) + 0.5)
            teeth.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{col}" stroke-width="{sw_w:.1f}" stroke-linecap="round"/>')
        return [f'<circle cx="{cx}" cy="{cy}" r="{scale*3.5:.1f}" fill="{col}" fill-opacity="0.4" {sw}/>'] + teeth
    elif role in ("CONTENT_UI", "STORAGE_UI"):
        return [
            f'<rect x="{cx - sc(8)}" y="{cy - sc(6)}" width="{sc(16)}" height="{sc(11)}" rx="{sc(2)}" fill="{col}" fill-opacity="0.15" {sw}/>',
            f'<line x1="{t(-3,5)}" x2="{t(3,5)}" {sw} fill="none"/>',
            f'<line x1="{t(0,5)}" x2="{t(0,8)}" {sw} fill="none"/>',
            f'<line x1="{t(-3,8)}" x2="{t(3,8)}" {sw} fill="none"/>',
        ]
    elif role == "SWARMFS":
        pts = " ".join(t(dx, dy) for dx, dy in [(-8,-3),(-8,7),(8,7),(8,-3),(1,-3),(-1,-6),(-4,-6),(-6,-3)])
        return [
            f'<polygon points="{pts}" fill="{col}" fill-opacity="0.2" {sw}/>',
            f'<line x1="{t(-4,2)}" x2="{t(4,2)}" stroke="{col}" stroke-width="{sw_w*0.67:.1f}" opacity="0.8"/>',
        ]
    elif role == "FOUNDATION_DB":
        return [
            f'<ellipse cx="{cx}" cy="{cy - sc(5)}" rx="{sc(7)}" ry="{sc(2)}" fill="{col}" fill-opacity="0.3" {sw}/>',
            f'<ellipse cx="{cx}" cy="{cy}" rx="{sc(7)}" ry="{sc(2)}" fill="{col}" fill-opacity="0.3" {sw}/>',
            f'<ellipse cx="{cx}" cy="{cy + sc(5)}" rx="{sc(7)}" ry="{sc(2)}" fill="{col}" fill-opacity="0.5" {sw}/>',
            f'<line x1="{t(-7,-5)}" x2="{t(-7,5)}" stroke="{col}" stroke-width="{sw_w*0.67:.1f}"/>',
            f'<line x1="{t(7,-5)}" x2="{t(7,5)}" stroke="{col}" stroke-width="{sw_w*0.67:.1f}"/>',
        ]
    elif role == "CSN_PLATFORM":
        r4, r5 = sc(4), sc(5)
        return [
            f'<path d="M {t(-7,3)} A {r4},{r4} 0 0 1 {t(-5,-4)} A {r5},{r5} 0 0 1 {t(5,-5)} A {r4},{r4} 0 0 1 {t(7,3)} Z" '
            f'fill="{col}" fill-opacity="0.25" {sw}/>',
        ]
    elif role == "TELEMETRY":
        return [
            f'<rect x="{cx - sc(7)}" y="{cy}" width="{sc(3)}" height="{sc(7)}" fill="{col}" fill-opacity="0.7"/>',
            f'<rect x="{cx - sc(3)}" y="{cy - sc(3)}" width="{sc(3)}" height="{sc(10)}" fill="{col}" fill-opacity="0.8"/>',
            f'<rect x="{cx + sc(1)}" y="{cy - sc(6)}" width="{sc(3)}" height="{sc(13)}" fill="{col}"/>',
            f'<rect x="{cx + sc(5)}" y="{cy - sc(2)}" width="{sc(3)}" height="{sc(9)}" fill="{col}" fill-opacity="0.7"/>',
            f'<line x1="{t(-8,8)}" x2="{t(8,8)}" stroke="{col}" stroke-width="{sw_w*0.67:.1f}"/>',
        ]
    return [
        f'<circle cx="{cx}" cy="{cy}" r="{sc(7)}" fill="{col}" fill-opacity="0.15" {sw}/>',
        f'<text x="{cx}" y="{cy + sc(4)}" text-anchor="middle" fill="{col}" font-size="{sc(11)}" font-weight="bold">?</text>',
    ]


def _layer_of(r: AuditResult) -> int:
    return ROLE_LAYERS.get(_primary_role(r), 6)


def _subnet_label(ip: str, prefix: str) -> str:
    try:
        return str(ipaddress.ip_interface(f"{ip}/{prefix}").network)
    except ValueError:
        return ""


def _ip_to_subnet(ip: str, subnet_map: dict[str, str]) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for cidr in subnet_map:
        try:
            if addr in ipaddress.ip_network(cidr):
                return cidr
        except ValueError:
            pass
    return ""


_ROLE_PKG_PRIORITY: dict[str, list[str]] = {
    "HAPROXY":              ["haproxy", "keepalived", "caringo-gateway"],
    "CONTENT_GATEWAY":      ["caringo-gateway", "caringo-cloudgateway"],
    "SCS":                  ["swarm-scs", "caringo-scs", "caringo-csn"],
    "STORAGE_UI":           ["caringo-storage-webui", "caringo-storageui"],
    "CONTENT_UI":           ["caringo-gateway-webui", "caringo-contentportal"],
    "SWARMFS":              ["caringo-swarmfs", "swarm-nfs"],
    "LISTING_CACHE":        ["rabbitmq", "redis", "memcached"],
    "LISTING_CACHE_SERVER": ["caringo-listingcache", "rabbitmq", "caringo-gateway"],
    "ELASTICSEARCH":        ["elasticsearch", "caringo-elasticsearch-search"],
    "CSN_PLATFORM":         ["swarm-scs", "caringo-csn"],
    "TELEMETRY":            ["swarm-telemetry", "prometheus"],
    "FOUNDATION_DB":        ["foundationdb-clients", "foundationdb-server"],
    "STORAGE_NODE":         [],
    "UNKNOWN":              [],
}


def _primary_package_ver(r: AuditResult) -> str:
    role = _primary_role(r)
    for prefix in _ROLE_PKG_PRIORITY.get(role, []):
        for pkg in r.installed_packages:
            if pkg.name.lower().startswith(prefix.lower()):
                return f"{pkg.name}-{pkg.version}"
    return ""


def _ip_suffix_for_mask(ip: str, prefix: str) -> str:
    try:
        plen = int(prefix)
        parts = ip.split(".")
        if len(parts) != 4:
            return ip
        if plen >= 24:
            return f".{parts[3]}"
        elif plen >= 16:
            return f".{parts[2]}.{parts[3]}"
        else:
            return f".{parts[1]}.{parts[2]}.{parts[3]}"
    except Exception:
        return ip


_IFACE_SKIP_PREFIXES = ("cni-", "podman", "docker", "veth", "virbr", "br-", "tun")


def _is_internal_iface(iface: str) -> bool:
    low = (iface or "").lower()
    return any(low.startswith(p) for p in _IFACE_SKIP_PREFIXES) or low == "lo"


def _build_subnet_colors(results: list[AuditResult]) -> dict[str, str]:
    raw: list[str] = []
    nodes_with_ifaces: set[str] = set()

    for r in results:
        for ni in r.network_interfaces:
            if not ni.ip or not ni.prefix or _is_internal_iface(ni.iface or "") or ":" in ni.ip:
                continue
            s = _subnet_label(ni.ip, ni.prefix)
            if s and s not in raw:
                raw.append(s)
            nodes_with_ifaces.add(r.server_id)

    for r in results:
        if r.server_id not in nodes_with_ifaces and r.server_ip and ":" not in r.server_ip:
            s = _subnet_label(r.server_ip, "24")
            if s and s not in raw:
                raw.append(s)

    for r in results:
        for sn in r.discovered_storage_nodes:
            if sn.ip and ":" not in sn.ip:
                s = _subnet_label(sn.ip, "24")
                if s and s not in raw:
                    raw.append(s)
        for es_node in r.discovered_es_nodes:
            if es_node.ip and ":" not in es_node.ip:
                s = _subnet_label(es_node.ip, "24")
                if s and s not in raw:
                    raw.append(s)

    try:
        nets = sorted([ipaddress.ip_network(c) for c in raw], key=lambda n: n.prefixlen)
        parent16: dict[str, list] = {}
        for net in nets:
            if net.prefixlen > 16:
                p16 = str(ipaddress.ip_network(f"{net.network_address}/16", strict=False))
                parent16.setdefault(p16, []).append(net)
        to_remove: set[str] = set()
        to_add: list = []
        existing_strs = {str(n) for n in nets}
        for p16_str, children in parent16.items():
            if len(children) >= 2:
                for c in children:
                    to_remove.add(str(c))
                if p16_str not in existing_strs:
                    to_add.append(ipaddress.ip_network(p16_str))
        nets = [n for n in nets if str(n) not in to_remove] + to_add
        nets = sorted(nets, key=lambda n: n.prefixlen)
        merged: list = []
        for net in nets:
            if not any(net.subnet_of(m) for m in merged):  # type: ignore
                merged.append(net)
        subnets = [str(n) for n in merged]
    except Exception:
        subnets = raw

    try:
        subnets = sorted(subnets, key=lambda c: (ipaddress.ip_network(c).prefixlen, ipaddress.ip_network(c).network_address))
    except Exception:
        subnets = sorted(subnets)
    return {s: SUBNET_PALETTE[i % len(SUBNET_PALETTE)] for i, s in enumerate(subnets)}


def _node_interfaces(r: AuditResult) -> list[tuple[str, str]]:
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for ni in r.network_interfaces:
        if ni.ip in seen or not ni.ip or not ni.prefix:
            continue
        if ni.ip == "127.0.0.1" or _is_internal_iface(ni.iface or "") or ":" in ni.ip:
            continue
        seen.add(ni.ip)
        out.append((ni.ip, ni.prefix))
    return out


def _node_cidrs_with_ips(r: AuditResult, subnet_colors: dict[str, str]) -> dict[str, list[str]]:
    cidr_ips: dict[str, list[str]] = {}
    for ip, prefix in _node_interfaces(r):
        cidr = _subnet_label(ip, prefix)
        if cidr and cidr in subnet_colors:
            cidr_ips.setdefault(cidr, []).append(ip)
    if not cidr_ips and r.server_ip:
        cidr = _ip_to_subnet(r.server_ip, subnet_colors)
        if cidr:
            cidr_ips[cidr] = [r.server_ip]
    return cidr_ips


# ─── Backbone classification ──────────────────────────────────────────────────

def _classify_backbone_sides(
    subnet_colors: dict[str, str],
    results: list[AuditResult],
) -> dict[str, str]:
    """
    Return cidr → 'left' | 'right' | 'top'.
    CIDRs only present in layer 0 (HAProxy) → 'top'.
    Remaining sorted by network address: index 0 → 'left', rest → 'right'.
    """
    cidr_layers: dict[str, set[int]] = {c: set() for c in subnet_colors}
    for r in results:
        layer = _layer_of(r)
        for ni in r.network_interfaces:
            if not ni.ip or not ni.prefix or _is_internal_iface(ni.iface or "") or ":" in ni.ip:
                continue
            cidr = _subnet_label(ni.ip, ni.prefix)
            if cidr in cidr_layers:
                cidr_layers[cidr].add(layer)

    top_cidrs: list[str] = []
    other_cidrs: list[str] = []
    for cidr, layers_set in cidr_layers.items():
        if layers_set and layers_set == {0}:
            top_cidrs.append(cidr)
        else:
            other_cidrs.append(cidr)

    try:
        other_cidrs.sort(key=lambda c: ipaddress.ip_network(c).network_address)
    except Exception:
        other_cidrs.sort()

    sides: dict[str, str] = {}
    for c in top_cidrs:
        sides[c] = "top"
    for i, c in enumerate(other_cidrs):
        sides[c] = "left" if i == 0 else "right"
    return sides


# ─── NIC badge data per server ────────────────────────────────────────────────

def _server_nic_data(
    r: AuditResult,
    cx: int,
    cy: int,
    backbone_sides: dict[str, str],
    subnet_colors: dict[str, str],
) -> tuple[list[dict], list[dict]]:
    """
    Return (left_nics, right_nics) for a server tile at (cx, cy).
    Each entry: {cx, cy, ip, cidr, iface, col}
    PUBLIC (left): badges stacked left-to-right starting at tile top-left body area.
    PRIVATE (right): badges stacked right-to-left starting at tile bottom-right body area.
    """
    tile_x = cx - NODE_W // 2
    tile_y = cy - NODE_H // 2

    left_nics_raw: list[tuple[str, str, str]] = []  # (ip, cidr, iface)
    right_nics_raw: list[tuple[str, str, str]] = []

    for ni in r.network_interfaces:
        if not ni.ip or not ni.prefix or _is_internal_iface(ni.iface or "") or ":" in ni.ip:
            continue
        cidr = _subnet_label(ni.ip, ni.prefix)
        side = backbone_sides.get(cidr, "")
        if side == "left":
            left_nics_raw.append((ni.ip, cidr, ni.iface or "eth"))
        elif side == "right":
            right_nics_raw.append((ni.ip, cidr, ni.iface or "eth"))

    # If no ifaces but server_ip found, try to place in left
    if not left_nics_raw and not right_nics_raw and r.server_ip:
        cidr = _ip_to_subnet(r.server_ip, subnet_colors)
        side = backbone_sides.get(cidr, "left")
        if side == "left":
            left_nics_raw.append((r.server_ip, cidr, "eth0"))
        elif side == "right":
            right_nics_raw.append((r.server_ip, cidr, "eth0"))

    # PUBLIC badges: top-left corner, x from left body start, y at tile top + margin
    pub_body_x0 = tile_x + LEFT_BTN_W + 6
    pub_badge_y  = tile_y + 3 + NIC_BADGE_H // 2

    left_nics: list[dict] = []
    for k, (ip, cidr, iface) in enumerate(left_nics_raw[:3]):
        badge_cx = pub_body_x0 + NIC_BADGE_W // 2 + k * NIC_BADGE_STEP
        # Don't overflow into right half — clamp
        if badge_cx + NIC_BADGE_W // 2 > tile_x + LEFT_BTN_W + INNER_BODY_W // 2 + 10:
            break
        left_nics.append({
            "cx": badge_cx, "cy": pub_badge_y,
            "ip": ip, "cidr": cidr, "iface": iface,
            "col": subnet_colors.get(cidr, "#3498db"),
            "entry_x": badge_cx,           # wire enters tile at this x
            "entry_y": tile_y,              # wire enters at tile TOP edge
        })

    # PRIVATE badges: bottom-right corner, x from right body end going left, y at tile bottom - margin
    prv_body_x1  = tile_x + BODY_W - 6
    prv_badge_y  = tile_y + NODE_H - 3 - NIC_BADGE_H // 2

    right_nics: list[dict] = []
    for k, (ip, cidr, iface) in enumerate(right_nics_raw[:3]):
        badge_cx = prv_body_x1 - NIC_BADGE_W // 2 - k * NIC_BADGE_STEP
        # Don't overflow into left half
        if badge_cx - NIC_BADGE_W // 2 < tile_x + LEFT_BTN_W + INNER_BODY_W // 2 - 10:
            break
        right_nics.append({
            "cx": badge_cx, "cy": prv_badge_y,
            "ip": ip, "cidr": cidr, "iface": iface,
            "col": subnet_colors.get(cidr, "#27ae60"),
            "entry_x": badge_cx,           # wire enters tile at this x
            "entry_y": tile_y + NODE_H,    # wire enters at tile BOTTOM edge
        })

    return left_nics, right_nics


def _draw_nic_badge(parts: list[str], bx: int, by: int, iface: str, ip: str, col: str) -> None:
    """Draw a NIC badge centered at (bx, by) inside the tile."""
    rx = bx - NIC_BADGE_W // 2
    ry = by - NIC_BADGE_H // 2
    iface_s = (iface or "eth")[:8]
    # Show last 2 octets of IP for brevity
    parts_ip = (ip or "").split(".")
    ip_s = ".".join(parts_ip[-2:]) if len(parts_ip) >= 2 else ip
    parts.append(
        f'  <rect x="{rx}" y="{ry}" width="{NIC_BADGE_W}" height="{NIC_BADGE_H}" '
        f'rx="3" fill="{col}" fill-opacity="0.18" stroke="{col}" stroke-width="1"/>'
    )
    parts.append(
        f'  <text x="{bx}" y="{ry + 9}" text-anchor="middle" '
        f'fill="{col}" font-size="8" font-weight="bold" font-family="{FONT}">{_esc(iface_s)}</text>'
    )
    parts.append(
        f'  <text x="{bx}" y="{ry + 18}" text-anchor="middle" '
        f'fill="{col}" font-size="7" font-family="{FONT}">{_esc(ip_s)}</text>'
    )


# ─── Wire routing per tile row ────────────────────────────────────────────────

def _draw_row_wires(
    parts: list[str],
    row: list[AuditResult],
    nic_data: dict[str, tuple[list[dict], list[dict]]],
    positions: dict[str, tuple[int, int]],
    tile_row_top: int,
    backbone_x_l: int,
    backbone_x_r: int,
) -> None:
    """
    Draw L-shaped wires for one tile row.
    PUBLIC: backbone_l → horizontal → drop to tile top → badge inside top-left.
    PRIVATE: backbone_r → horizontal → rise to tile bottom → badge inside bottom-right.
    Anti-crossing: sort by badge x asc (public) / desc (private), assign routing levels.
    """
    tile_row_bottom = tile_row_top + NODE_H

    # Collect all left NICs in this row: (badge_cx, entry_x, entry_y, ip, cidr, iface, col, sid)
    left_entries: list[dict] = []
    right_entries: list[dict] = []

    for r in row:
        if r.server_id not in positions or r.server_id not in nic_data:
            continue
        left_nics, right_nics = nic_data[r.server_id]
        for n in left_nics:
            left_entries.append(dict(n))
        for n in right_nics:
            right_entries.append(dict(n))

    # PUBLIC wires: sort by badge_cx ascending (leftmost = k=0 = closest routing level)
    left_entries.sort(key=lambda e: e["cx"])
    for k, e in enumerate(left_entries):
        routing_y = tile_row_top - (k + 1) * WIRE_STEP
        col = e["col"]
        bx, entry_x, entry_y = e["cx"], e["entry_x"], e["entry_y"]

        # Glow
        parts.append(
            f'  <polyline points="{backbone_x_l},{routing_y} {entry_x},{routing_y} {entry_x},{entry_y}" '
            f'stroke="{col}" stroke-width="6" fill="none" opacity="0.08" '
            f'stroke-linecap="round" stroke-linejoin="round"/>'
        )
        # Wire
        parts.append(
            f'  <polyline points="{backbone_x_l},{routing_y} {entry_x},{routing_y} {entry_x},{entry_y}" '
            f'stroke="{col}" stroke-width="{WIRE_STROKE}" fill="none" opacity="0.85" '
            f'stroke-linecap="round" stroke-linejoin="round"/>'
        )
        # Dot on backbone
        parts.append(f'  <circle cx="{backbone_x_l}" cy="{routing_y}" r="3.5" fill="{col}" opacity="0.9"/>')
        parts.append(f'  <circle cx="{backbone_x_l}" cy="{routing_y}" r="1.5" fill="#0c1524" opacity="0.8"/>')

    # PRIVATE wires: sort by badge_cx descending (rightmost = k=0 = closest routing level)
    right_entries.sort(key=lambda e: e["cx"], reverse=True)
    for k, e in enumerate(right_entries):
        routing_y = tile_row_bottom + (k + 1) * WIRE_STEP
        col = e["col"]
        entry_x, entry_y = e["entry_x"], e["entry_y"]

        # Glow
        parts.append(
            f'  <polyline points="{backbone_x_r},{routing_y} {entry_x},{routing_y} {entry_x},{entry_y}" '
            f'stroke="{col}" stroke-width="6" fill="none" opacity="0.08" '
            f'stroke-linecap="round" stroke-linejoin="round"/>'
        )
        # Wire
        parts.append(
            f'  <polyline points="{backbone_x_r},{routing_y} {entry_x},{routing_y} {entry_x},{entry_y}" '
            f'stroke="{col}" stroke-width="{WIRE_STROKE}" fill="none" opacity="0.85" '
            f'stroke-linecap="round" stroke-linejoin="round"/>'
        )
        # Dot on backbone
        parts.append(f'  <circle cx="{backbone_x_r}" cy="{routing_y}" r="3.5" fill="{col}" opacity="0.9"/>')
        parts.append(f'  <circle cx="{backbone_x_r}" cy="{routing_y}" r="1.5" fill="#0c1524" opacity="0.8"/>')


# ─── Main SVG generator ───────────────────────────────────────────────────────

def generate_svg(results: list[AuditResult]) -> str:
    if not results:
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 100" '
            'style="display:block;width:100%;height:auto;background:#0c1524;">'
            '<text x="20" y="50" font-family="monospace" fill="#94a3b8">'
            'No audit results yet.</text></svg>'
        )

    # ── IP → node index ───────────────────────────────────────────────────────
    ip_to_id: dict[str, str] = {}
    for r in results:
        ip_to_id[r.server_ip] = r.server_id
        for ni in r.network_interfaces:
            if ni.ip not in ip_to_id:
                ip_to_id[ni.ip] = r.server_id

    subnet_colors = _build_subnet_colors(results)
    backbone_sides = _classify_backbone_sides(subnet_colors, results)

    has_left  = any(s == "left"  for s in backbone_sides.values())
    has_right = any(s == "right" for s in backbone_sides.values())
    has_top   = any(s == "top"   for s in backbone_sides.values())

    # ── Layer assignment ──────────────────────────────────────────────────────
    layers: dict[int, list[AuditResult]] = {}
    for r in results:
        layers.setdefault(_layer_of(r), []).append(r)

    # ── Discovered storage nodes ──────────────────────────────────────────────
    swarmctl_lookup: dict[str, DiscoveredStorageNode] = {}
    audited_ips: set[str] = set()
    for r in results:
        audited_ips.add(r.server_ip)
        for ni in r.network_interfaces:
            if ni.ip and ":" not in ni.ip and ni.ip not in ("127.0.0.1",):
                audited_ips.add(ni.ip)
    best_sn: dict[str, DiscoveredStorageNode] = {}
    for r in results:
        for sn in r.discovered_storage_nodes:
            if sn.ip in audited_ips:
                continue
            existing = best_sn.get(sn.ip)
            if existing is None:
                best_sn[sn.ip] = sn
            elif sn.health_report is not None and existing.health_report is None:
                best_sn[sn.ip] = sn
    for ip, sn in best_sn.items():
        audited_ips.add(ip)
        sid = f"disc-storage-{ip}"
        chassis_id = ""
        if sn.health_report and isinstance(sn.health_report, dict):
            chassis_id = str(sn.health_report.get("SNMP objects", {}).get("Chassis Id") or "")
        display_name = chassis_id[:16] if chassis_id else ip
        fake = AuditResult(
            server_id=sid, server_name=display_name, server_ip=ip,
            success=(sn.status == "ok"),
            hostname=chassis_id or None,
            os=f"{sn.used}/{sn.max} · {sn.streams} str · v{sn.version}",
            roles=[{"role": "STORAGE_NODE", "reason": f"swarmctl: {sn.status}"}],
        )
        swarmctl_lookup[sid] = sn
        layers.setdefault(5, []).append(fake)
        ip_to_id[ip] = sid

    # ── Discovered ES nodes ───────────────────────────────────────────────────
    _audited_names: dict[str, str] = {}
    for _r in results:
        _audited_names[_r.server_name.lower()] = _r.server_id
        if _r.hostname:
            _audited_names[_r.hostname.lower()] = _r.server_id
    for r in results:
        cluster_hint = f" [{r.es_cluster_name}]" if r.es_cluster_name else ""
        for es_node in r.discovered_es_nodes:
            if es_node.ip not in audited_ips:
                if es_node.name:
                    existing_sid = _audited_names.get(es_node.name.lower())
                    if existing_sid:
                        ip_to_id[es_node.ip] = existing_sid
                        audited_ips.add(es_node.ip)
                        continue
                audited_ips.add(es_node.ip)
                fake = AuditResult(
                    server_id=f"disc-es-{es_node.ip}",
                    server_name=es_node.name or es_node.ip,
                    server_ip=es_node.ip, success=False,
                    error=f"Discovered via ES{cluster_hint}",
                    roles=[{"role": "ELASTICSEARCH", "reason": f"ES discovery{cluster_hint}"}],
                    es_cluster_name=r.es_cluster_name,
                )
                layers.setdefault(4, []).append(fake)
                ip_to_id[es_node.ip] = fake.server_id

    if not layers:
        return '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="80"><text x="20" y="40" font-family="monospace" fill="#e74c3c">No results.</text></svg>'

    # ── Split each layer into sub-rows ────────────────────────────────────────
    active_layers = sorted(layers.keys())
    layer_sub_rows: dict[int, list[list[AuditResult]]] = {}
    for li in active_layers:
        nodes = layers[li]
        rows = [nodes[i:i + MAX_COLS_PER_ROW] for i in range(0, len(nodes), MAX_COLS_PER_ROW)]
        layer_sub_rows[li] = rows

    max_cols_actual = max(
        max(len(row) for row in rows)
        for rows in layer_sub_rows.values()
    ) if layer_sub_rows else 1

    # ── Backbone layout & wire space ──────────────────────────────────────────
    # Count max NIC connections per row to size wire bundles
    max_nl = max_nr = 0
    for li in active_layers:
        for row in layer_sub_rows[li]:
            nl = nr = 0
            for r in row:
                for ni in r.network_interfaces:
                    if not ni.ip or not ni.prefix or _is_internal_iface(ni.iface or "") or ":" in ni.ip:
                        continue
                    cidr = _subnet_label(ni.ip, ni.prefix)
                    side = backbone_sides.get(cidr, "")
                    if side == "left":
                        nl += 1
                    elif side == "right":
                        nr += 1
            max_nl = max(max_nl, nl)
            max_nr = max(max_nr, nr)
    max_nl = max(max_nl, 1)
    max_nr = max(max_nr, 1)

    wire_space_above = max_nl * WIRE_STEP + WIRE_ROW_MARGIN
    wire_space_below = max_nr * WIRE_STEP + WIRE_ROW_MARGIN

    # ── Layout computation ────────────────────────────────────────────────────
    y_cursor = TILE_V_PAD + wire_space_above
    if has_top:
        y_cursor = max(y_cursor, BACKBONE_PAD_TOP + wire_space_above)

    layer_row_tops: dict[int, list[int]] = {}
    for li_idx, li in enumerate(active_layers):
        rows = layer_sub_rows[li]
        row_tops: list[int] = []
        for ri in range(len(rows)):
            row_tops.append(y_cursor)
            if ri < len(rows) - 1:
                y_cursor += NODE_H + wire_space_below + SUB_ROW_GAP + wire_space_above
            else:
                y_cursor += NODE_H
        layer_row_tops[li] = row_tops
        y_cursor += LABEL_H
        if li_idx < len(active_layers) - 1:
            y_cursor += wire_space_below + MIN_LAYER_GAP + wire_space_above

    # ── Tile positions ────────────────────────────────────────────────────────
    tile_area_w = max_cols_actual * NODE_W + (max_cols_actual - 1) * H_GAP
    pad_l = BACKBONE_PAD_L if has_left else TILE_MARGIN_X
    pad_r = BACKBONE_PAD_R if has_right else TILE_MARGIN_X
    total_w = pad_l + tile_area_w + TILE_MARGIN_X + pad_r

    grid_step = NODE_W + H_GAP
    positions: dict[str, tuple[int, int]] = {}
    for li in active_layers:
        rows = layer_sub_rows[li]
        row_tops = layer_row_tops[li]
        for j, row_nodes in enumerate(rows):
            n_nodes = len(row_nodes)
            col_offset = (max_cols_actual - n_nodes) // 2
            cy = row_tops[j] + NODE_H // 2
            for k, r in enumerate(row_nodes):
                cx = pad_l + TILE_MARGIN_X + (col_offset + k) * grid_step + NODE_W // 2
                positions[r.server_id] = (cx, cy)

    # ── Pre-compute NIC badge data per server ─────────────────────────────────
    nic_data: dict[str, tuple[list[dict], list[dict]]] = {}
    for r in results:
        if r.server_id not in positions:
            continue
        cx, cy = positions[r.server_id]
        nic_data[r.server_id] = _server_nic_data(r, cx, cy, backbone_sides, subnet_colors)
    # Also for discovered nodes (no real interfaces, skip)
    all_nodes_flat = [r for li in active_layers for row in layer_sub_rows[li] for r in row]
    for r in all_nodes_flat:
        if r.server_id not in nic_data and r.server_id in positions:
            cx, cy = positions[r.server_id]
            nic_data[r.server_id] = _server_nic_data(r, cx, cy, backbone_sides, subnet_colors)

    # ── SVG dimensions ────────────────────────────────────────────────────────
    last_li       = active_layers[-1]
    last_row_top  = layer_row_tops[last_li][-1]
    tile_area_bot = last_row_top + NODE_H + LABEL_H + wire_space_below
    legend_h      = max(60, 20 + len(subnet_colors) * 18 + 8)
    total_h       = tile_area_bot + TILE_V_PAD + legend_h

    backbone_x_l = BACKBONE_X_INSET
    backbone_x_r = total_w - BACKBONE_X_INSET

    # Backbone vertical extent
    first_li       = active_layers[0]
    first_row_top  = layer_row_tops[first_li][0]
    bb_y_start     = first_row_top - wire_space_above
    bb_y_end       = tile_area_bot

    # ── SVG assembly ──────────────────────────────────────────────────────────
    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {total_w} {total_h}" '
        f'preserveAspectRatio="xMidYMid meet" '
        f'data-natural-w="{total_w}" data-natural-h="{total_h}" '
        f'style="background:#0c1524;font-family:{FONT};display:block;width:100%;height:auto;">'
    )

    # Arrowhead markers
    parts.append('  <defs>')
    parts.append('    <marker id="swarm-arrow" viewBox="0 0 10 10" refX="9" refY="5"')
    parts.append('            markerWidth="7" markerHeight="7" orient="auto-start-reverse">')
    parts.append('      <path d="M0,0 L10,5 L0,10 z" fill="#f59e0b" opacity="0.95"/>')
    parts.append('    </marker>')
    for role, col in ROLE_COLORS.items():
        mid = role.replace("_", "-").lower()
        parts.append(
            f'    <marker id="arr-{mid}" viewBox="0 0 10 10" refX="9" refY="5"'
            f' markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        )
        parts.append(f'      <path d="M0,0 L10,5 L0,10 z" fill="{col}" opacity="0.95"/>')
        parts.append('    </marker>')
    parts.append('  </defs>')

    # ── Vertical backbone lines ────────────────────────────────────────────────
    # Collect CIDRs per side for labels
    cidrs_left  = [c for c, s in backbone_sides.items() if s == "left"]
    cidrs_right = [c for c, s in backbone_sides.items() if s == "right"]

    if has_left:
        col = subnet_colors.get(cidrs_left[0], "#4a9eff") if cidrs_left else "#4a9eff"
        # Glow
        parts.append(
            f'  <line x1="{backbone_x_l}" y1="{bb_y_start}" x2="{backbone_x_l}" y2="{bb_y_end}" '
            f'stroke="{col}" stroke-width="{BACKBONE_STROKE + 10}" opacity="0.08" stroke-linecap="round"/>'
        )
        # Main line
        parts.append(
            f'  <line x1="{backbone_x_l}" y1="{bb_y_start}" x2="{backbone_x_l}" y2="{bb_y_end}" '
            f'stroke="{col}" stroke-width="{BACKBONE_STROKE}" opacity="0.90" stroke-linecap="round"/>'
        )
        # End caps
        for ey in (bb_y_start, bb_y_end):
            parts.append(
                f'  <line x1="{backbone_x_l - 6}" y1="{ey}" x2="{backbone_x_l + 6}" y2="{ey}" '
                f'stroke="{col}" stroke-width="2.5" opacity="0.8" stroke-linecap="round"/>'
            )
        # Labels
        for i, cidr in enumerate(cidrs_left):
            col_c = subnet_colors.get(cidr, col)
            parts.append(
                f'  <text x="{backbone_x_l + 8}" y="{bb_y_start + 12 + i * 14}" '
                f'fill="{col_c}" font-size="9" font-weight="bold" font-family="{FONT}">'
                f'{_esc(cidr)} PUB</text>'
            )

    if has_right:
        col = subnet_colors.get(cidrs_right[0], "#52d48a") if cidrs_right else "#52d48a"
        parts.append(
            f'  <line x1="{backbone_x_r}" y1="{bb_y_start}" x2="{backbone_x_r}" y2="{bb_y_end}" '
            f'stroke="{col}" stroke-width="{BACKBONE_STROKE + 10}" opacity="0.08" stroke-linecap="round"/>'
        )
        parts.append(
            f'  <line x1="{backbone_x_r}" y1="{bb_y_start}" x2="{backbone_x_r}" y2="{bb_y_end}" '
            f'stroke="{col}" stroke-width="{BACKBONE_STROKE}" opacity="0.90" stroke-linecap="round"/>'
        )
        for ey in (bb_y_start, bb_y_end):
            parts.append(
                f'  <line x1="{backbone_x_r - 6}" y1="{ey}" x2="{backbone_x_r + 6}" y2="{ey}" '
                f'stroke="{col}" stroke-width="2.5" opacity="0.8" stroke-linecap="round"/>'
            )
        for i, cidr in enumerate(cidrs_right):
            col_c = subnet_colors.get(cidr, col)
            parts.append(
                f'  <text x="{backbone_x_r - 8}" y="{bb_y_start + 12 + i * 14}" text-anchor="end" '
                f'fill="{col_c}" font-size="9" font-weight="bold" font-family="{FONT}">'
                f'{_esc(cidr)} PRV</text>'
            )

    # ── HAProxy top horizontal backbone ───────────────────────────────────────
    if has_top:
        top_y = BACKBONE_PAD_TOP // 2
        cidrs_top = [c for c, s in backbone_sides.items() if s == "top"]
        for i, cidr in enumerate(cidrs_top):
            by = top_y + i * 18
            col = subnet_colors.get(cidr, "#e74c3c")
            parts.append(
                f'  <line x1="{pad_l}" y1="{by}" x2="{pad_l + tile_area_w + TILE_MARGIN_X}" y2="{by}" '
                f'stroke="{col}" stroke-width="{BACKBONE_STROKE + 8}" opacity="0.08" stroke-linecap="round"/>'
            )
            parts.append(
                f'  <line x1="{pad_l}" y1="{by}" x2="{pad_l + tile_area_w + TILE_MARGIN_X}" y2="{by}" '
                f'stroke="{col}" stroke-width="{BACKBONE_STROKE}" opacity="0.90" stroke-linecap="round"/>'
            )
            parts.append(
                f'  <text x="{pad_l}" y="{by - 4}" '
                f'fill="{col}" font-size="9" font-weight="bold" font-family="{FONT}">'
                f'{_esc(cidr)} HA</text>'
            )
            # Vertical wires down to HAProxy tiles (layer 0)
            if 0 in layer_sub_rows:
                for row in layer_sub_rows[0]:
                    for r in row:
                        if r.server_id not in positions:
                            continue
                        cx, cy = positions[r.server_id]
                        tile_top = cy - NODE_H // 2
                        parts.append(
                            f'  <line x1="{cx}" y1="{by}" x2="{cx}" y2="{tile_top}" '
                            f'stroke="{col}" stroke-width="{WIRE_STROKE}" opacity="0.75" stroke-dasharray="4,3"/>'
                        )

    # ── Layer bands ───────────────────────────────────────────────────────────
    for li in active_layers:
        row_tops    = layer_row_tops[li]
        band_top    = row_tops[0] - 6
        band_bottom = row_tops[-1] + NODE_H + LABEL_H + 8
        band_h      = band_bottom - band_top
        label       = LAYER_LABELS.get(li, f"Layer {li}")
        parts.append(
            f'  <rect x="{pad_l + TILE_MARGIN_X - 10}" y="{band_top}" '
            f'width="{tile_area_w + 20}" height="{band_h}" '
            f'rx="10" fill="#1e3050" opacity="0.18" stroke="#2a4a70" stroke-width="1" stroke-opacity="0.45"/>'
        )
        parts.append(
            f'  <text x="{pad_l + TILE_MARGIN_X}" y="{band_bottom - 4}" '
            f'fill="#4a5a9a" font-size="13" font-style="italic" font-family="{FONT}">{_esc(label)}</text>'
        )

    # ── VIP badge ─────────────────────────────────────────────────────────────
    if 0 in layers:
        all_vips: list[str] = []
        for r in layers[0]:
            for vip in r.haproxy_vips:
                v = vip.split("/")[0]
                if v not in all_vips:
                    all_vips.append(v)
        if all_vips:
            vip_text = "VIP " + "  ·  ".join(all_vips)
            vip_tw   = len(vip_text) * 8 + 20
            mid_x    = pad_l + tile_area_w // 2 + TILE_MARGIN_X
            vip_tx   = mid_x - vip_tw // 2
            vip_ty   = layer_row_tops[0][0] - 22
            parts.append(
                f'  <rect x="{vip_tx}" y="{vip_ty}" width="{vip_tw}" height="18" '
                f'rx="6" fill="#e67e22" opacity="0.95"/>'
            )
            parts.append(
                f'  <text x="{mid_x}" y="{vip_ty + 13}" text-anchor="middle" '
                f'fill="#0f0f1e" font-size="11" font-weight="bold">{_esc(vip_text)}</text>'
            )

    # ── L-shaped wires (draw BEFORE tiles so tiles overlay wire entry points) ─
    for li in active_layers:
        rows = layer_sub_rows[li]
        row_tops = layer_row_tops[li]
        for j, row in enumerate(rows):
            _draw_row_wires(
                parts, row, nic_data, positions,
                row_tops[j], backbone_x_l, backbone_x_r,
            )

    # ── ES cluster badge ──────────────────────────────────────────────────────
    if 4 in layers:
        es_names: list[str] = []
        for r in layers[4]:
            if r.es_cluster_name and r.es_cluster_name not in es_names:
                es_names.append(r.es_cluster_name)
        if es_names:
            row_tops = layer_row_tops[4]
            last_row_bottom_es = row_tops[-1] + NODE_H + 4
            es_cxs = [positions[r.server_id][0] for r in layers[4] if r.server_id in positions]
            if es_cxs:
                band_mid  = (min(es_cxs) + max(es_cxs)) // 2
                es_label  = "  ·  ".join(es_names)
                badge_w   = len(es_label) * 7 + 20
                parts.append(
                    f'  <rect x="{band_mid - badge_w//2}" y="{last_row_bottom_es}" '
                    f'width="{badge_w}" height="16" rx="5" fill="#5b2c8d" opacity="0.92"/>'
                )
                parts.append(
                    f'  <text x="{band_mid}" y="{last_row_bottom_es + 11}" text-anchor="middle" '
                    f'fill="#d7bde2" font-size="10" font-weight="bold">{_esc(es_label)}</text>'
                )

    # ── Connection overlay placeholder ────────────────────────────────────────
    parts.append('  <g id="swarm-overlay"></g>')

    # ── Server node cards ─────────────────────────────────────────────────────
    for r in all_nodes_flat:
        if r.server_id not in positions:
            continue
        cx, cy = positions[r.server_id]
        role    = _primary_role(r)
        color   = ROLE_COLORS.get(role, "#7f8c8d")
        x, y    = cx - NODE_W // 2, cy - NODE_H // 2
        is_disc = r.server_id.startswith("disc-")
        show_json = not is_disc or r.server_id.startswith("disc-storage-")

        border_color = "#2d4a6b" if r.success else ("#e67e22" if is_disc else "#c0392b")
        border_width = "2" if is_disc else ("1.5" if r.success else "2")

        lstrip_cx = x + LEFT_BTN_W // 2
        body_cx   = x + LEFT_BTN_W + INNER_BODY_W // 2

        # 1. Card background
        parts.append(
            f'  <rect x="{x}" y="{y}" width="{NODE_W}" height="{NODE_H}" '
            f'rx="10" fill="#162032" stroke="{border_color}" stroke-width="{border_width}"/>'
        )

        # 2. Right role strip
        strip_x = x + BODY_W
        parts.append(
            f'  <rect x="{strip_x}" y="{y+1}" width="{ROLE_STRIP_W-1}" height="{NODE_H-2}" '
            f'rx="9" fill="{color}" fill-opacity="0.88"/>'
        )
        parts.append(
            f'  <rect x="{strip_x}" y="{y+1}" width="12" height="{NODE_H-2}" '
            f'fill="{color}" fill-opacity="0.88"/>'
        )
        parts.append(
            f'  <line x1="{strip_x}" y1="{y+4}" x2="{strip_x}" y2="{y+NODE_H-4}" '
            f'stroke="{color}" stroke-width="1.5" opacity="0.6"/>'
        )
        strip_cx = strip_x + ROLE_STRIP_W // 2

        if is_disc:
            status_sym, status_col = "◈", "#e67e22"
        elif r.success:
            status_sym, status_col = "✓", "#4ade80"
        else:
            status_sym, status_col = "✗", "#f87171"
        parts.append(
            f'  <text x="{strip_cx}" y="{y+17}" text-anchor="middle" '
            f'fill="{status_col}" font-size="13" font-weight="bold" font-family="{FONT}">'
            f'{_esc(status_sym)}</text>'
        )

        role_labels = [ROLE_SHORT.get(rd.role, rd.role) for rd in r.roles] if r.roles else ["?"]
        for ri, rl in enumerate(role_labels[:4]):
            parts.append(
                f'  <text x="{strip_cx}" y="{y+33+ri*14}" text-anchor="middle" '
                f'fill="#ffffff" font-size="9" font-weight="bold" font-family="{FONT}">'
                f'{_esc(rl)}</text>'
            )

        # 2c. Left button strip
        parts.append(
            f'  <line x1="{x+LEFT_BTN_W}" y1="{y+6}" x2="{x+LEFT_BTN_W}" y2="{y+NODE_H-6}" '
            f'stroke="{color}" stroke-width="0.8" opacity="0.35"/>'
        )
        BTN_W   = LEFT_BTN_W - 8
        BTN_H   = 14
        det_by  = y + NODE_H // 2 - BTN_H - 2
        json_by = y + NODE_H // 2 + 2

        parts.append(f'  <a href="#" onclick="svgNodeDetails(event,&quot;{_esc(r.server_id)}&quot;)" style="cursor:pointer">')
        parts.append(f'  <rect x="{x+4}" y="{det_by}" width="{BTN_W}" height="{BTN_H}" rx="3" fill="#1e3a5f" stroke="#2563eb" stroke-width="1" opacity="0.95"/>')
        parts.append(f'  <text x="{lstrip_cx}" y="{det_by+10}" text-anchor="middle" fill="#93c5fd" font-size="8" font-family="{FONT}">Det.</text>')
        parts.append('  </a>')

        if show_json:
            parts.append(f'  <a href="/api/audit/dump/{_esc(r.server_id)}" target="_blank" onclick="event.stopPropagation()">')
            parts.append(f'  <rect x="{x+4}" y="{json_by}" width="{BTN_W}" height="{BTN_H}" rx="3" fill="#162032" stroke="#475569" stroke-width="1" opacity="0.95"/>')
            parts.append(f'  <text x="{lstrip_cx}" y="{json_by+10}" text-anchor="middle" fill="#64748b" font-size="8" font-family="{FONT}">JSON</text>')
            parts.append('  </a>')

        # 3. Role icon
        icon_cy = y + 52
        parts.extend(_role_icon_svg(role, color, body_cx, icon_cy, scale=2.5))

        # 4. Server name
        name_str = (r.server_name[:20] + "…") if len(r.server_name) > 20 else r.server_name
        parts.append(
            f'  <text x="{body_cx}" y="{y + 90}" text-anchor="middle" '
            f'fill="#f1f5f9" font-size="14" font-weight="bold" font-family="{FONT}">'
            f'{_esc(name_str)}</text>'
        )

        # 5. Storage node capacity bar
        sn_data = swarmctl_lookup.get(r.server_id)
        if sn_data is not None:
            try:
                _used_pct = 100 - int(sn_data.avail_pct.replace("%", "").strip())
            except (ValueError, AttributeError):
                _used_pct = 0
            bar_y  = y + NODE_H - 42
            bar_w  = INNER_BODY_W - 16
            filled = int(bar_w * _used_pct / 100)
            bar_col = "#e74c3c" if _used_pct > 85 else ("#f39c12" if _used_pct > 70 else "#27ae60")
            parts.append(
                f'  <text x="{body_cx}" y="{bar_y - 3}" text-anchor="middle" '
                f'fill="#bdc3c7" font-size="8" font-family="{FONT}">'
                f'{_esc(sn_data.used)}/{_esc(sn_data.max)} · {_esc(sn_data.streams)} str</text>'
            )
            parts.append(f'  <rect x="{x+LEFT_BTN_W+8}" y="{bar_y}" width="{bar_w}" height="6" rx="3" fill="#2c3e50"/>')
            if filled > 0:
                parts.append(f'  <rect x="{x+LEFT_BTN_W+8}" y="{bar_y}" width="{filled}" height="6" rx="3" fill="{bar_col}"/>')

        # 6. Error / disc indicator
        if not r.success and r.error:
            err = (r.error[:22] + "…") if len(r.error) > 22 else r.error
            parts.append(
                f'  <text x="{body_cx}" y="{y+NODE_H-26}" text-anchor="middle" '
                f'fill="#f87171" font-size="8" font-family="{FONT}">{_esc(err)}</text>'
            )
        elif is_disc:
            parts.append(
                f'  <text x="{body_cx}" y="{y+NODE_H-26}" text-anchor="middle" '
                f'fill="#e67e22" font-size="8" font-style="italic" font-family="{FONT}">discovered</text>'
            )

        # 7. NIC badges — PUBLIC top-left, PRIVATE bottom-right (inside tile)
        left_nics, right_nics = nic_data.get(r.server_id, ([], []))
        for n in left_nics:
            _draw_nic_badge(parts, n["cx"], n["cy"], n["iface"], n["ip"], n["col"])
        for n in right_nics:
            _draw_nic_badge(parts, n["cx"], n["cy"], n["iface"], n["ip"], n["col"])

        # 8. Transparent click overlay
        parts.append(
            f'  <rect x="{x}" y="{y}" width="{BODY_W}" height="{NODE_H}" '
            f'fill="none" style="cursor:pointer" '
            f'onclick="svgNodeClick(event,&quot;{_esc(r.server_id)}&quot;)"/>'
        )

    # ── Legend ────────────────────────────────────────────────────────────────
    if subnet_colors:
        side_labels = {"left": "PUB", "right": "PRV", "top": "HA"}
        nlw = 210
        nlh = 20 + len(subnet_colors) * 18 + 8
        nlx = total_w - nlw - 12
        nly = total_h - nlh - 8
        parts.append(f'  <rect x="{nlx}" y="{nly}" width="{nlw}" height="{nlh}" rx="6" fill="#162032" opacity="0.85" stroke="#2d4a6b" stroke-width="1"/>')
        parts.append(f'  <text x="{nlx+8}" y="{nly+14}" fill="#94a3b8" font-size="10" font-weight="bold">Networks</text>')
        for i, (cidr, col) in enumerate(subnet_colors.items()):
            iy   = nly + 22 + i * 18
            side = backbone_sides.get(cidr, "")
            slbl = side_labels.get(side, "")
            parts.append(f'  <rect x="{nlx+8}" y="{iy}" width="12" height="10" rx="2" fill="{col}"/>')
            parts.append(f'  <text x="{nlx+26}" y="{iy+9}" fill="{col}" font-size="9">{_esc(cidr)}</text>')
            if slbl:
                parts.append(f'  <text x="{nlx+nlw-8}" y="{iy+9}" text-anchor="end" fill="{col}" font-size="8" opacity="0.7">[{slbl}]</text>')

    # ── Embedded node meta for JS connection overlay ───────────────────────────
    node_meta: dict = {}
    for r in all_nodes_flat:
        if r.server_id not in positions:
            continue
        cx2, cy2 = positions[r.server_id]
        all_ips_list = [r.server_ip]
        for ni in r.network_interfaces:
            if ni.ip and ni.ip not in all_ips_list and ":" not in ni.ip and ni.ip != "127.0.0.1":
                all_ips_list.append(ni.ip)

        live_conns = [
            {"dst": c.remote_addr, "port": c.remote_port, "proc": (c.process or "")[:20], "cfg": False}
            for c in r.connections
            if c.remote_addr not in ("", "0.0.0.0", "*")
        ]
        cfg_conns: list[dict] = []
        for be in r.haproxy_backends:
            ip = (be.ip or "").split(":")[0]
            if ip:
                cfg_conns.append({"dst": ip, "port": be.port or "80", "proc": "haproxy-backend", "cfg": True})
        for addr in r.gw_cluster_ips:
            ip, _, port = addr.partition(":")
            if ip:
                cfg_conns.append({"dst": ip, "port": port or "80", "proc": "gw→storage", "cfg": True})
        for addr in r.gw_es_ips:
            ip, _, port = addr.partition(":")
            if ip:
                cfg_conns.append({"dst": ip, "port": port or "9200", "proc": "gw→es", "cfg": True})
        for addr in r.gw_lcs_ips:
            ip, _, port = addr.partition(":")
            if ip:
                cfg_conns.append({"dst": ip, "port": port or "6379", "proc": "gw→lcs", "cfg": True})

        node_meta[r.server_id] = {
            "cx": cx2, "cy": cy2,
            "hw": NODE_W // 2, "hh": NODE_H // 2,
            "name": r.server_name,
            "role": _primary_role(r),
            "role_color": ROLE_COLORS.get(_primary_role(r), "#7f8c8d"),
            "ips": all_ips_list,
            "conns": live_conns + cfg_conns,
            "listen": [{"port": lp.port, "proc": (lp.process or "")[:20]} for lp in r.listen_ports],
        }

    # ── Implied infrastructure flows ──────────────────────────────────────────
    svc_ips: dict[str, list[str]] = {"syslog": [], "ntp": [], "dhcp": [], "pxe": []}
    for r2 in all_nodes_flat:
        if r2.server_id not in positions:
            continue
        if r2.is_syslog_server: svc_ips["syslog"].append(r2.server_ip)
        if r2.is_ntp_server:    svc_ips["ntp"].append(r2.server_ip)
        if r2.is_dhcp_server:   svc_ips["dhcp"].append(r2.server_ip)
        if r2.is_pxe_server:    svc_ips["pxe"].append(r2.server_ip)
    _scs_fallback = [r2.server_ip for r2 in all_nodes_flat if any(rd.role == "SCS" for rd in r2.roles)]
    for _svc in svc_ips:
        if not svc_ips[_svc] and _scs_fallback:
            svc_ips[_svc] = _scs_fallback

    for r2 in all_nodes_flat:
        if r2.server_id not in node_meta:
            continue
        m = node_meta[r2.server_id]
        r2_ips = set(m["ips"])
        primary = m["role"]
        for _svc, _server_ips in svc_ips.items():
            for _sip in _server_ips:
                if _sip in r2_ips:
                    continue
                if _svc == "syslog":
                    m["conns"].append({"dst": _sip, "port": "514", "proc": "syslog", "cfg": True})
                elif _svc == "ntp":
                    m["conns"].append({"dst": _sip, "port": "123", "proc": "ntp", "cfg": True})
                elif _svc == "dhcp" and primary == "STORAGE_NODE":
                    m["conns"].append({"dst": _sip, "port": "67", "proc": "dhcp", "cfg": True})
                elif _svc == "pxe" and primary == "STORAGE_NODE":
                    m["conns"].append({"dst": _sip, "port": "69", "proc": "pxe/tftp", "cfg": True})

    meta_json_str = _json.dumps({"nodes": node_meta, "ip_to_id": ip_to_id}, separators=(",", ":"))
    parts.append(f'  <desc id="swarm-node-data">{_html_mod.escape(meta_json_str)}</desc>')
    parts.append("</svg>")
    return "\n".join(parts)
