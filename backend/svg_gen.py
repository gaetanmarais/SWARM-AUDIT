# Version: 10.0.0
# Date:    2026-06-19
# Notes:   Horizontal backbone buses (full-width lines per subnet), vertical stubs
#          from tile edges to backbone — replaces vertical side-backbone design

from __future__ import annotations
import html as _html_mod
import ipaddress
import json as _json
import math as _math
from models import AuditResult, DiscoveredStorageNode

# ─── Role → display layer ─────────────────────────────────────────────────────
ROLE_LAYERS: dict[str, int] = {
    "HAPROXY":              0,
    "CONTENT_GATEWAY":      1,
    "SCS":                  1,
    "STORAGE_UI":           2,
    "CONTENT_UI":           2,
    "SWARMFS":              2,
    "LISTING_CACHE":        3,
    "LISTING_CACHE_SERVER": 3,
    "ELASTICSEARCH":        4,
    "CSN_PLATFORM":         4,
    "TELEMETRY":            4,
    "FOUNDATION_DB":        5,
    "STORAGE_NODE":         5,
    "UNKNOWN":              6,
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
    0: "Load Balancer",
    1: "Gateway / Services",
    2: "UI / NFS",
    3: "Cache (LCS)",
    4: "Search / Management",
    5: "Storage",
    6: "Unknown",
}

SUBNET_PALETTE = [
    "#3498db", "#27ae60", "#e74c3c", "#f39c12",
    "#9b59b6", "#1abc9c", "#e67e22",
]

# ─── Layout constants ─────────────────────────────────────────────────────────
NODE_W            = 280
NODE_H            = 155
ROLE_STRIP_W      = 58
LEFT_BTN_W        = 40
BODY_W            = NODE_W - ROLE_STRIP_W
INNER_BODY_W      = BODY_W - LEFT_BTN_W
H_GAP             = 100
V_GAP_BASE        = 20    # minimum gap between layers when no backbone lines
SUB_ROW_GAP       = 28
MAX_COLS_PER_ROW  = 6
TILE_MARGIN_X     = 15    # horizontal margin from SVG edge to tile area
LABEL_H           = 26
FONT              = "Arial, sans-serif"

# ─── Horizontal backbone constants ───────────────────────────────────────────
BUS_THICKNESS     = 6      # backbone line stroke-width
BUS_SPACING       = 22     # vertical spacing between stacked backbones in same gap
BUS_GAP_PAD_TOP   = 12    # padding from top of gap to first backbone center
BUS_GAP_PAD_BOT   = 12    # padding from last backbone center to bottom of gap
BUS_STUB_CAP      = 8     # half-width of T-bar at tile-edge connection
BUS_DOT_R         = 5     # ring-dot radius on backbone
BUS_LABEL_X_PAD   = 6     # x padding for CIDR label from SVG left/right edge


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
        return [
            f'<polygon points="{pts}" fill="{col}" fill-opacity="0.7" stroke="{col}" stroke-width="{sw_w*0.33:.1f}"/>',
        ]
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
        return [
            f'<circle cx="{cx}" cy="{cy}" r="{scale*3.5:.1f}" fill="{col}" fill-opacity="0.4" {sw}/>',
        ] + teeth
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


# ─── Horizontal backbone placement ───────────────────────────────────────────

def _assign_subnets_to_gaps(
    active_layers: list[int],
    layer_sub_rows: dict[int, list[list[AuditResult]]],
    subnet_colors: dict[str, str],
) -> dict[str, int]:
    """
    Return cidr → gap_position.
    Gap position i = gap BEFORE active_layers[i] (i.e. between layers[i-1] and layers[i]).
    Gap 0 = above the first layer.
    Gap n = below the last layer (n = len(active_layers)).
    Backbone is placed in the gap AFTER the topmost (smallest-index) layer using it.
    """
    cidr_layer_positions: dict[str, set[int]] = {c: set() for c in subnet_colors}
    for pos, li in enumerate(active_layers):
        nodes = [r for row in layer_sub_rows[li] for r in row]
        for r in nodes:
            for ni in r.network_interfaces:
                if not ni.ip or not ni.prefix or _is_internal_iface(ni.iface or "") or ":" in ni.ip:
                    continue
                cidr = _subnet_label(ni.ip, ni.prefix)
                if cidr in cidr_layer_positions:
                    cidr_layer_positions[cidr].add(pos)

    gap_assign: dict[str, int] = {}
    n = len(active_layers)
    for cidr, positions in cidr_layer_positions.items():
        if not positions:
            gap_assign[cidr] = 0
        else:
            # Backbone sits in the gap right AFTER the topmost layer using this subnet
            min_pos = min(positions)
            gap_assign[cidr] = min(min_pos + 1, n)
    return gap_assign


def _compute_gap_height(n_backbones: int) -> int:
    if n_backbones == 0:
        return V_GAP_BASE
    return BUS_GAP_PAD_TOP + n_backbones * BUS_SPACING + BUS_GAP_PAD_BOT


# ─── Layout computation (backbone-aware) ─────────────────────────────────────

def _compute_layout(
    active_layers: list[int],
    layer_sub_rows: dict[int, list[list[AuditResult]]],
    gap_counts: dict[int, int],   # gap_position → number of backbone lines
) -> tuple[dict[int, list[int]], dict[int, int]]:
    """
    Returns (layer_row_tops, gap_start_ys).
    gap_start_ys[pos] = y where the gap at position pos begins.
    pos 0 = above first layer; pos i = between layers[i-1] and layers[i].
    """
    layer_row_tops: dict[int, list[int]] = {}
    gap_start_ys: dict[int, int] = {}
    y = 0
    for pos, li in enumerate(active_layers):
        gh = _compute_gap_height(gap_counts.get(pos, 0))
        gap_start_ys[pos] = y
        y += gh
        rows = layer_sub_rows.get(li, [[]])
        row_tops: list[int] = []
        for j in range(len(rows)):
            row_tops.append(y)
            if j < len(rows) - 1:
                y += NODE_H + SUB_ROW_GAP
        layer_row_tops[li] = row_tops
        y += NODE_H + LABEL_H
    # gap after last layer
    gap_start_ys[len(active_layers)] = y
    return layer_row_tops, gap_start_ys


def _compute_backbone_ys(
    gap_assign: dict[str, int],
    gap_start_ys: dict[int, int],
) -> dict[str, int]:
    """Return cidr → y coordinate of the horizontal backbone line."""
    groups: dict[int, list[str]] = {}
    for cidr, pos in gap_assign.items():
        groups.setdefault(pos, []).append(cidr)
    for pos in groups:
        groups[pos] = sorted(groups[pos])  # deterministic ordering

    backbone_y: dict[str, int] = {}
    for pos, cidrs in groups.items():
        y_base = gap_start_ys.get(pos, 0) + BUS_GAP_PAD_TOP
        for k, cidr in enumerate(cidrs):
            backbone_y[cidr] = y_base + k * BUS_SPACING + BUS_SPACING // 2
    return backbone_y


# ─── Main SVG generator ───────────────────────────────────────────────────────

def generate_svg(results: list[AuditResult]) -> str:
    if not results:
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" width="800" height="100">'
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

    # ── Layer assignment ──────────────────────────────────────────────────────
    layers: dict[int, list[AuditResult]] = {}
    for r in results:
        layers.setdefault(_layer_of(r), []).append(r)

    # ── Discovered storage nodes — deduplicate by IP ──────────────────────────
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
            server_id=sid,
            server_name=display_name,
            server_ip=ip,
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
                    server_ip=es_node.ip,
                    success=False,
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

    total_w = TILE_MARGIN_X * 2 + max_cols_actual * NODE_W + (max_cols_actual - 1) * H_GAP

    # ── Backbone placement ────────────────────────────────────────────────────
    gap_assign = _assign_subnets_to_gaps(active_layers, layer_sub_rows, subnet_colors)
    gap_counts: dict[int, int] = {}
    for pos in gap_assign.values():
        gap_counts[pos] = gap_counts.get(pos, 0) + 1

    # ── Layout computation (backbone-aware) ───────────────────────────────────
    layer_row_tops, gap_start_ys = _compute_layout(active_layers, layer_sub_rows, gap_counts)
    backbone_y = _compute_backbone_ys(gap_assign, gap_start_ys)

    # ── Node positions — grid-aligned ─────────────────────────────────────────
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
                cx = TILE_MARGIN_X + (col_offset + k) * grid_step + NODE_W // 2
                positions[r.server_id] = (cx, cy)

    # ── SVG dimensions ────────────────────────────────────────────────────────
    last_li         = active_layers[-1]
    last_row_top    = layer_row_tops[last_li][-1]
    last_row_bottom = last_row_top + NODE_H + LABEL_H
    # add height for any backbone lines below the last layer
    n_after_last = gap_counts.get(len(active_layers), 0)
    after_gap_h  = _compute_gap_height(n_after_last)

    legend_h = max(60, 16 + len(subnet_colors) * 16 + 8)
    total_h  = last_row_bottom + after_gap_h + legend_h

    all_nodes_flat = [r for li in active_layers for row in layer_sub_rows[li] for r in row]

    # ── SVG assembly ──────────────────────────────────────────────────────────
    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {total_w} {total_h}" '
        f'width="{total_w}" height="{total_h}" '
        f'style="background:#0c1524;font-family:{FONT};display:block;">'
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

    # ── Horizontal backbone buses ─────────────────────────────────────────────
    for cidr, by in backbone_y.items():
        col = subnet_colors.get(cidr, "#94a3b8")
        # Glow
        parts.append(
            f'  <line x1="0" y1="{by}" x2="{total_w}" y2="{by}" '
            f'stroke="{col}" stroke-width="{BUS_THICKNESS + 10}" opacity="0.10" stroke-linecap="butt"/>'
        )
        # Main line
        parts.append(
            f'  <line x1="0" y1="{by}" x2="{total_w}" y2="{by}" '
            f'stroke="{col}" stroke-width="{BUS_THICKNESS}" opacity="0.88" stroke-linecap="butt"/>'
        )
        # Vertical end caps (left & right)
        for ex in (0, total_w):
            parts.append(
                f'  <line x1="{ex}" y1="{by - BUS_THICKNESS}" x2="{ex}" y2="{by + BUS_THICKNESS}" '
                f'stroke="{col}" stroke-width="3" opacity="0.8" stroke-linecap="round"/>'
            )
        # CIDR label at both ends (above the line)
        parts.append(
            f'  <text x="{BUS_LABEL_X_PAD}" y="{by - 5}" '
            f'fill="{col}" font-size="9" font-weight="bold" font-family="{FONT}">{_esc(cidr)}</text>'
        )
        parts.append(
            f'  <text x="{total_w - BUS_LABEL_X_PAD}" y="{by - 5}" text-anchor="end" '
            f'fill="{col}" font-size="9" font-weight="bold" font-family="{FONT}">{_esc(cidr)}</text>'
        )

    # ── Layer bands ───────────────────────────────────────────────────────────
    for li in active_layers:
        row_tops    = layer_row_tops[li]
        band_top    = row_tops[0] - 6
        band_bottom = row_tops[-1] + NODE_H + LABEL_H + 8
        band_h      = band_bottom - band_top
        label       = LAYER_LABELS.get(li, f"Layer {li}")
        parts.append(
            f'  <rect x="{TILE_MARGIN_X - 10}" y="{band_top}" '
            f'width="{total_w - TILE_MARGIN_X * 2 + 20}" height="{band_h}" '
            f'rx="10" fill="#1e3050" opacity="0.18" stroke="#2a4a70" stroke-width="1" stroke-opacity="0.45"/>'
        )
        parts.append(
            f'  <text x="{TILE_MARGIN_X}" y="{band_bottom - 4}" '
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
            vip_tx   = total_w // 2 - vip_tw // 2
            vip_ty   = layer_row_tops[0][0] - 22
            parts.append(
                f'  <rect x="{vip_tx}" y="{vip_ty}" width="{vip_tw}" height="18" '
                f'rx="6" fill="#e67e22" opacity="0.95"/>'
            )
            parts.append(
                f'  <text x="{total_w // 2}" y="{vip_ty + 13}" text-anchor="middle" '
                f'fill="#0f0f1e" font-size="11" font-weight="bold">{_esc(vip_text)}</text>'
            )

    # ── Vertical stubs: tile → horizontal backbone ────────────────────────────
    # Each tile connects to each subnet backbone via a vertical stub.
    # If the backbone is above the tile → stub exits from tile TOP going UP.
    # If the backbone is below the tile → stub exits from tile BOTTOM going DOWN.
    # Multiple subnets per tile are spread horizontally across the tile width.

    for r in all_nodes_flat:
        if r.server_id not in positions:
            continue
        cx, cy = positions[r.server_id]
        tile_top    = cy - NODE_H // 2
        tile_bottom = cy + NODE_H // 2

        cidr_ips   = _node_cidrs_with_ips(r, subnet_colors)
        subs_sorted = [c for c in sorted(cidr_ips.keys()) if c in backbone_y]
        n = len(subs_sorted)
        if n == 0:
            continue

        for si, cidr in enumerate(subs_sorted):
            by  = backbone_y[cidr]
            col = subnet_colors[cidr]
            prefix = cidr.split("/")[1] if "/" in cidr else "24"

            # Spread stubs horizontally: centre on cx, 22px apart
            sx = cx + round((si - (n - 1) / 2) * 22)

            # Exit from tile TOP (backbone above) or BOTTOM (backbone below)
            if by <= tile_top:
                sy = tile_top
                lbl_y = sy - 3
                lbl_anchor = "middle"
            else:
                sy = tile_bottom
                lbl_y = sy + 10
                lbl_anchor = "middle"

            # Vertical stub line
            parts.append(
                f'  <line x1="{sx}" y1="{sy}" x2="{sx}" y2="{by}" '
                f'stroke="{col}" stroke-width="2" opacity="0.72"/>'
            )
            # T-cap at tile edge
            parts.append(
                f'  <line x1="{sx - BUS_STUB_CAP}" y1="{sy}" x2="{sx + BUS_STUB_CAP}" y2="{sy}" '
                f'stroke="{col}" stroke-width="3" stroke-linecap="round"/>'
            )
            # Ring-dot on backbone
            parts.append(
                f'  <circle cx="{sx}" cy="{by}" r="{BUS_DOT_R}" fill="{col}" opacity="0.95"/>'
            )
            parts.append(
                f'  <circle cx="{sx}" cy="{by}" r="{BUS_DOT_R - 2}" fill="#0c1524" opacity="0.85"/>'
            )
            # IP label beside the stub cap
            for ip in cidr_ips[cidr]:
                ip_lbl = _ip_suffix_for_mask(ip, prefix)
                parts.append(
                    f'  <text x="{sx}" y="{lbl_y}" text-anchor="{lbl_anchor}" '
                    f'fill="{col}" font-size="8" font-weight="bold" font-family="{FONT}">'
                    f'{_esc(ip_lbl)}</text>'
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
        role   = _primary_role(r)
        color  = ROLE_COLORS.get(role, "#7f8c8d")
        x, y   = cx - NODE_W // 2, cy - NODE_H // 2
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

        # 2a. Status icon
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

        # 2b. Role abbreviations in strip
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

        parts.append(
            f'  <a href="#" onclick="svgNodeDetails(event,&quot;{_esc(r.server_id)}&quot;)" style="cursor:pointer">'
        )
        parts.append(
            f'  <rect x="{x+4}" y="{det_by}" width="{BTN_W}" height="{BTN_H}" rx="3" '
            f'fill="#1e3a5f" stroke="#2563eb" stroke-width="1" opacity="0.95"/>'
        )
        parts.append(
            f'  <text x="{lstrip_cx}" y="{det_by+10}" text-anchor="middle" '
            f'fill="#93c5fd" font-size="8" font-family="{FONT}">Det.</text>'
        )
        parts.append('  </a>')

        if show_json:
            parts.append(
                f'  <a href="/api/audit/dump/{_esc(r.server_id)}" target="_blank"'
                f' onclick="event.stopPropagation()">'
            )
            parts.append(
                f'  <rect x="{x+4}" y="{json_by}" width="{BTN_W}" height="{BTN_H}" rx="3" '
                f'fill="#162032" stroke="#475569" stroke-width="1" opacity="0.95"/>'
            )
            parts.append(
                f'  <text x="{lstrip_cx}" y="{json_by+10}" text-anchor="middle" '
                f'fill="#64748b" font-size="8" font-family="{FONT}">JSON</text>'
            )
            parts.append('  </a>')

        # 3. Role icon
        icon_cy = y + 48
        parts.extend(_role_icon_svg(role, color, body_cx, icon_cy, scale=2.5))

        # 4. Server name
        name_str = (r.server_name[:20] + "…") if len(r.server_name) > 20 else r.server_name
        name_y   = y + 82
        parts.append(
            f'  <text x="{body_cx}" y="{name_y}" text-anchor="middle" '
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
            bar_y   = y + NODE_H - 40
            bar_w   = INNER_BODY_W - 16
            filled  = int(bar_w * _used_pct / 100)
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
                f'  <text x="{body_cx}" y="{y+NODE_H-6}" text-anchor="middle" '
                f'fill="#f87171" font-size="8" font-family="{FONT}">{_esc(err)}</text>'
            )
        elif is_disc:
            parts.append(
                f'  <text x="{body_cx}" y="{y+NODE_H-6}" text-anchor="middle" '
                f'fill="#e67e22" font-size="8" font-style="italic" font-family="{FONT}">discovered</text>'
            )

        # 7. NIC interface badges — one small badge per subnet, top of body area
        cidr_ips_tile = _node_cidrs_with_ips(r, subnet_colors)
        badge_x = x + LEFT_BTN_W + 4
        for bk, (bcidr, bips) in enumerate(cidr_ips_tile.items()):
            bcol   = subnet_colors.get(bcidr, "#94a3b8")
            bx_pos = badge_x + bk * 38
            by_pos = y + 4
            if bx_pos + 36 > x + BODY_W - 4:
                break  # no room
            # Find iface name for this cidr
            iface_lbl = "eth"
            for ni in r.network_interfaces:
                if not ni.ip or not ni.prefix or _is_internal_iface(ni.iface or "") or ":" in ni.ip:
                    continue
                if _subnet_label(ni.ip, ni.prefix) == bcidr:
                    iface_lbl = (ni.iface or "eth")[:6]
                    break
            parts.append(
                f'  <rect x="{bx_pos}" y="{by_pos}" width="36" height="14" '
                f'rx="3" fill="{bcol}" fill-opacity="0.12" '
                f'stroke="{bcol}" stroke-width="1" stroke-opacity="0.65"/>'
            )
            parts.append(
                f'  <text x="{bx_pos + 4}" y="{by_pos + 10}" '
                f'fill="{bcol}" font-size="8" font-family="{FONT}">{_esc(iface_lbl)}</text>'
            )

        # 8. Transparent click overlay
        parts.append(
            f'  <rect x="{x}" y="{y}" width="{BODY_W}" height="{NODE_H}" '
            f'fill="none" style="cursor:pointer" '
            f'onclick="svgNodeClick(event,&quot;{_esc(r.server_id)}&quot;)"/>'
        )

    # ── Legend ────────────────────────────────────────────────────────────────
    if subnet_colors:
        nlw = 190
        nlh = 18 + len(subnet_colors) * 16 + 8
        nlx = total_w - nlw - 12
        nly = total_h - nlh - 8
        parts.append(
            f'  <rect x="{nlx}" y="{nly}" width="{nlw}" height="{nlh}" '
            f'rx="6" fill="#162032" opacity="0.85" stroke="#2d4a6b" stroke-width="1"/>'
        )
        parts.append(
            f'  <text x="{nlx+8}" y="{nly+14}" fill="#94a3b8" font-size="10" font-weight="bold">Networks</text>'
        )
        for i, (cidr, col) in enumerate(subnet_colors.items()):
            iy = nly + 24 + i * 16
            parts.append(f'  <rect x="{nlx+8}" y="{iy}" width="12" height="10" rx="2" fill="{col}"/>')
            parts.append(f'  <text x="{nlx+26}" y="{iy+9}" fill="{col}" font-size="9">{_esc(cidr)}</text>')

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
            {"dst": c.remote_addr, "port": c.remote_port,
             "proc": (c.process or "")[:20], "cfg": False}
            for c in r.connections
            if c.remote_addr not in ("", "0.0.0.0", "*")
        ]

        cfg_conns: list[dict] = []
        for be in r.haproxy_backends:
            ip = (be.ip or "").split(":")[0]
            if ip:
                cfg_conns.append({"dst": ip, "port": be.port or "80",
                                   "proc": "haproxy-backend", "cfg": True})
        for addr in r.gw_cluster_ips:
            ip, _, port = addr.partition(":")
            if ip:
                cfg_conns.append({"dst": ip, "port": port or "80",
                                   "proc": "gw→storage", "cfg": True})
        for addr in r.gw_es_ips:
            ip, _, port = addr.partition(":")
            if ip:
                cfg_conns.append({"dst": ip, "port": port or "9200",
                                   "proc": "gw→es", "cfg": True})
        for addr in r.gw_lcs_ips:
            ip, _, port = addr.partition(":")
            if ip:
                cfg_conns.append({"dst": ip, "port": port or "6379",
                                   "proc": "gw→lcs", "cfg": True})

        node_meta[r.server_id] = {
            "cx": cx2, "cy": cy2,
            "hw": NODE_W // 2,
            "hh": NODE_H // 2,
            "name": r.server_name,
            "role": _primary_role(r),
            "role_color": ROLE_COLORS.get(_primary_role(r), "#7f8c8d"),
            "ips": all_ips_list,
            "conns": live_conns + cfg_conns,
            "listen": [
                {"port": lp.port, "proc": (lp.process or "")[:20]}
                for lp in r.listen_ports
            ],
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
    _scs_fallback = [
        r2.server_ip for r2 in all_nodes_flat
        if any(rd.role == "SCS" for rd in r2.roles)
    ]
    for _svc in svc_ips:
        if not svc_ips[_svc] and _scs_fallback:
            svc_ips[_svc] = _scs_fallback

    for r2 in all_nodes_flat:
        if r2.server_id not in node_meta:
            continue
        m      = node_meta[r2.server_id]
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

    meta_json_str = _json.dumps(
        {"nodes": node_meta, "ip_to_id": ip_to_id},
        separators=(",", ":"),
    )
    parts.append(f'  <desc id="swarm-node-data">{_html_mod.escape(meta_json_str)}</desc>')
    parts.append("</svg>")
    return "\n".join(parts)
