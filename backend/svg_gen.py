# Version: 6.2.0
# Date:    2026-06-18
# Notes:   SVG responsive (width:100%), icons larger (scale=1.75), badges inside tile
#          with short inner-wire, IP suffix based on mask, layer bands lighter.

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

NODE_W           = 280
NODE_H           = 155
ROLE_STRIP_W     = 58   # right-side vertical role strip width
BODY_W           = NODE_W - ROLE_STRIP_W   # main card body width (222px)
BADGE_PAD        = 4    # gap between tile edge and IP badge (inside)
BADGE_H_S        = 14   # IP badge height (small, inside tile edge)
H_GAP            = 65
V_GAP            = 105
SUB_ROW_GAP      = 28   # vertical gap between sub-rows within the same layer
MAX_COLS_PER_ROW = 6    # wrap layer into multiple rows when node count exceeds this
MARGIN_X         = 75
MARGIN_Y         = 75
LABEL_H          = 26
FONT             = "Arial, sans-serif"
BUS_H            = 30
BUS_PAD          = 12


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
    """Return SVG element strings for a role icon centered at (cx, cy). scale ≈ 1.0 → ~16px."""
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


def _ip_suffix(ip: str) -> str:
    parts = ip.split(".")
    return f".{parts[2]}.{parts[3]}" if len(parts) == 4 else ip


def _ip_suffix_for_mask(ip: str, prefix: str) -> str:
    """Return host-significant suffix of IP based on prefix length."""
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

    # Phase 1: declared interfaces of SSH-audited nodes
    for r in results:
        for ni in r.network_interfaces:
            if not ni.ip or not ni.prefix or _is_internal_iface(ni.iface or "") or ":" in ni.ip:
                continue
            s = _subnet_label(ni.ip, ni.prefix)
            if s and s not in raw:
                raw.append(s)
            nodes_with_ifaces.add(r.server_id)

    # Phase 2: audited nodes with no usable interfaces — infer /24 from server_ip
    for r in results:
        if r.server_id not in nodes_with_ifaces and r.server_ip and ":" not in r.server_ip:
            s = _subnet_label(r.server_ip, "24")
            if s and s not in raw:
                raw.append(s)

    # Phase 3: IPs of nodes discovered via swarmctl / ES API (not in results directly)
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

    # Auto-summarize: ≥2 /24+ under same /16 → replace with /16
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

    # Sort by prefix length then by network address for deterministic color assignment
    # so colors don't change between audit runs regardless of completion order
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


# ─── Layout computation (multi-row per layer) ─────────────────────────────────

def _compute_layout(
    active_layers: list[int],
    layer_sub_rows: dict[int, list[list[AuditResult]]],
    subnet_colors: dict[str, str],
) -> tuple[dict[int, list[int]], dict[str, int], dict[str, int]]:
    """
    Returns:
      layer_row_tops[layer_idx] = [y_subrow0, y_subrow1, ...]
      bus_y[cidr]
      cidr_to_gap[cidr] = gap index (0..n-2) between active_layers
    """
    n = len(active_layers)

    # Flatten nodes per layer for CIDR lookup
    layers_flat = {
        li: [r for row in rows for r in row]
        for li, rows in layer_sub_rows.items()
    }

    # CIDR presence per layer
    layer_cidrs: list[set[str]] = [set() for _ in range(n)]
    for i, li in enumerate(active_layers):
        for r in layers_flat.get(li, []):
            for cidr in _node_cidrs_with_ips(r, subnet_colors):
                if cidr in subnet_colors:
                    layer_cidrs[i].add(cidr)

    # Assign each CIDR to ONE gap
    cidr_to_gap: dict[str, int] = {}
    for cidr in subnet_colors:
        if n > 1 and cidr in layer_cidrs[n - 1]:
            cidr_to_gap[cidr] = n - 2
            continue
        best_gap: int | None = None
        best_score = -1
        for g in range(n - 1):
            in_above = cidr in layer_cidrs[g]
            in_below = cidr in layer_cidrs[g + 1]
            if in_above or in_below:
                score = 2 if (in_above and in_below) else 1
                if score > best_score:
                    best_score = score
                    best_gap = g
        if best_gap is not None:
            cidr_to_gap[cidr] = best_gap

    gap_to_cidrs: dict[int, list[str]] = {}
    for cidr, g in cidr_to_gap.items():
        gap_to_cidrs.setdefault(g, []).append(cidr)
    for g in gap_to_cidrs:
        gap_to_cidrs[g] = sorted(gap_to_cidrs[g])

    # Compute Y positions — each layer may have multiple sub-rows
    layer_row_tops: dict[int, list[int]] = {}
    y = MARGIN_Y
    for i, li in enumerate(active_layers):
        rows = layer_sub_rows.get(li, [[]])
        num_rows = len(rows)
        row_tops: list[int] = []
        for j in range(num_rows):
            row_tops.append(y)
            if j < num_rows - 1:
                # Gap between sub-rows within same layer (no bus here)
                y += NODE_H + SUB_ROW_GAP
        layer_row_tops[li] = row_tops

        # Advance y past the last sub-row, then add V_GAP + bus space for next gap
        buses_in_gap = len(gap_to_cidrs.get(i, []))
        extra = max(0, buses_in_gap * BUS_H + BUS_PAD * 2 - V_GAP)
        y += NODE_H + LABEL_H + V_GAP + extra

    # Bus Y: placed below the LAST sub-row of the layer above the gap
    bus_y: dict[str, int] = {}
    for g, cidrs in gap_to_cidrs.items():
        li_above = active_layers[g]
        last_row_top = layer_row_tops[li_above][-1]
        base_y = last_row_top + NODE_H + LABEL_H + BUS_PAD
        for k, cidr in enumerate(cidrs):
            bus_y[cidr] = base_y + k * BUS_H + BUS_H // 2

    return layer_row_tops, bus_y, cidr_to_gap


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

    # ── Discovered storage nodes — deduplicate by IP, prefer health_report ────
    swarmctl_lookup: dict[str, DiscoveredStorageNode] = {}  # server_id → sn
    audited_ips = {r.server_ip for r in results}
    best_sn: dict[str, DiscoveredStorageNode] = {}  # ip → best DiscoveredStorageNode

    for r in results:
        for sn in r.discovered_storage_nodes:
            if sn.ip in audited_ips:
                continue
            existing = best_sn.get(sn.ip)
            if existing is None:
                best_sn[sn.ip] = sn
            elif sn.health_report is not None and existing.health_report is None:
                best_sn[sn.ip] = sn  # upgrade to the one with health data

    for ip, sn in best_sn.items():
        audited_ips.add(ip)
        sid = f"disc-storage-{ip}"
        # Use Chassis ID as display name when available (more stable than IP)
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
    # Index audited nodes by hostname/name to dedup against multi-NIC servers
    _audited_names: dict[str, str] = {}  # name.lower() → server_id
    for _r in results:
        _audited_names[_r.server_name.lower()] = _r.server_id
        if _r.hostname:
            _audited_names[_r.hostname.lower()] = _r.server_id

    for r in results:
        cluster_hint = f" [{r.es_cluster_name}]" if r.es_cluster_name else ""
        for es_node in r.discovered_es_nodes:
            if es_node.ip not in audited_ips:
                # If the discovered name matches an audited server, just register the IP alias
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

    total_w = MARGIN_X * 2 + max_cols_actual * NODE_W + (max_cols_actual - 1) * H_GAP

    # ── Layout computation ────────────────────────────────────────────────────
    layer_row_tops, bus_y, cidr_to_gap = _compute_layout(
        active_layers, layer_sub_rows, subnet_colors
    )

    # ── Node positions ────────────────────────────────────────────────────────
    positions: dict[str, tuple[int, int]] = {}
    for li in active_layers:
        rows = layer_sub_rows[li]
        row_tops = layer_row_tops[li]
        for j, row_nodes in enumerate(rows):
            n_nodes = len(row_nodes)
            row_w = n_nodes * NODE_W + (n_nodes - 1) * H_GAP
            x_start = (total_w - row_w) // 2
            cy = row_tops[j] + NODE_H // 2
            for k, r in enumerate(row_nodes):
                cx = x_start + k * (NODE_W + H_GAP) + NODE_W // 2
                positions[r.server_id] = (cx, cy)

    # ── SVG dimensions ────────────────────────────────────────────────────────
    last_li = active_layers[-1]
    last_row_top = layer_row_tops[last_li][-1]
    last_row_bottom = last_row_top + NODE_H + LABEL_H
    legend_h = max(60, 16 + len(subnet_colors) * 16 + 8)
    total_h = last_row_bottom + V_GAP + legend_h + MARGIN_Y

    all_nodes_flat = [r for li in active_layers for row in layer_sub_rows[li] for r in row]

    # ── SVG assembly ──────────────────────────────────────────────────────────
    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {total_w} {total_h}" '
        f'width="{total_w}" height="{total_h}" '
        f'style="background:#0c1524;font-family:{FONT};display:block;">'
    )

    # Arrowhead marker for connection overlay
    parts.append('  <defs>')
    parts.append('    <marker id="swarm-arrow" viewBox="0 0 10 10" refX="9" refY="5"')
    parts.append('            markerWidth="7" markerHeight="7" orient="auto-start-reverse">')
    parts.append('      <path d="M0,0 L10,5 L0,10 z" fill="#f59e0b" opacity="0.95"/>')
    parts.append('    </marker>')
    # Per-role arrow markers
    for role, col in ROLE_COLORS.items():
        mid = role.replace("_", "-").lower()
        parts.append(
            f'    <marker id="arr-{mid}" viewBox="0 0 10 10" refX="9" refY="5"'
            f' markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        )
        parts.append(f'      <path d="M0,0 L10,5 L0,10 z" fill="{col}" opacity="0.95"/>')
        parts.append('    </marker>')
    parts.append('  </defs>')

    # ── Layer bands (span all sub-rows) ───────────────────────────────────────
    for li in active_layers:
        row_tops = layer_row_tops[li]
        band_top    = row_tops[0] - 6
        band_bottom = row_tops[-1] + NODE_H + LABEL_H + 8
        band_h      = band_bottom - band_top
        label       = LAYER_LABELS.get(li, f"Layer {li}")
        parts.append(
            f'  <rect x="{MARGIN_X//2}" y="{band_top}" '
            f'width="{total_w - MARGIN_X}" height="{band_h}" '
            f'rx="10" fill="#1e3050" opacity="0.18" stroke="#2a4a70" stroke-width="1" stroke-opacity="0.45"/>'
        )
        parts.append(
            f'  <text x="{MARGIN_X}" y="{band_bottom - 4}" '
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

    # ── Bus lines ─────────────────────────────────────────────────────────────
    bus_x_left  = MARGIN_X
    bus_x_right = total_w - MARGIN_X

    for cidr, by in sorted(bus_y.items(), key=lambda kv: kv[1]):
        col = subnet_colors.get(cidr, "#7f8c8d")
        parts.append(
            f'  <line x1="{bus_x_left}" y1="{by}" x2="{bus_x_right}" y2="{by}" '
            f'stroke="{col}" stroke-width="4" opacity="0.85"/>'
        )
        parts.append(
            f'  <line x1="{bus_x_left}" y1="{by-3}" x2="{bus_x_right}" y2="{by-3}" '
            f'stroke="{col}" stroke-width="1" opacity="0.4"/>'
        )
        _lw = len(cidr) * 7 + 10
        for side_x, anchor in [(bus_x_left + 6, "start"), (bus_x_right - 6, "end")]:
            _rx = side_x - 4 if anchor == "start" else side_x - _lw + 4
            parts.append(
                f'  <rect x="{_rx}" y="{by - 17}" width="{_lw}" height="14" '
                f'rx="3" fill="#0c1524" opacity="0.75"/>'
            )
            parts.append(
                f'  <text x="{side_x}" y="{by - 6}" text-anchor="{anchor}" '
                f'fill="{col}" font-size="11" font-weight="bold">{_esc(cidr)}</text>'
            )

    # ── Node-to-bus stubs (wire + bus circle only; IP badges drawn on tiles) ────
    # node_badges[server_id] = list of (stub_cx, direction, ip_str, iface_str, col)
    node_badges: dict = {}

    for i, li in enumerate(active_layers):
        rows = layer_sub_rows[li]
        row_tops = layer_row_tops[li]
        for j, row_nodes in enumerate(rows):
            for r in row_nodes:
                if r.server_id not in positions:
                    continue
                cx, cy = positions[r.server_id]
                node_top    = cy - NODE_H // 2
                node_bottom = cy + NODE_H // 2

                cidr_ips = _node_cidrs_with_ips(r, subnet_colors)
                all_cidrs = list(cidr_ips.keys())
                n_stubs = len(all_cidrs)

                for stub_idx, cidr in enumerate(all_cidrs):
                    by = bus_y.get(cidr)
                    if by is None:
                        continue
                    col = subnet_colors[cidr]
                    direction = "up" if by < cy else "down"

                    # Stubs within body; 18px margin leaves room for badge width
                    body_left  = cx - NODE_W // 2 + 18
                    body_right = cx - NODE_W // 2 + BODY_W - 18
                    if n_stubs == 1:
                        stub_cx = (body_left + body_right) // 2
                    else:
                        stub_cx = int(body_left + stub_idx * (body_right - body_left) / max(n_stubs - 1, 1))

                    stub_node_y = node_top if direction == "up" else node_bottom
                    line_start_y = stub_node_y  # wire connects exactly at tile edge

                    stub_len = abs(by - line_start_y)
                    stub_w   = "2.5" if stub_len > NODE_H * 2 else "1.5"
                    parts.append(
                        f'  <line x1="{stub_cx}" y1="{line_start_y}" '
                        f'x2="{stub_cx}" y2="{by}" '
                        f'stroke="{col}" stroke-width="{stub_w}" opacity="0.80"/>'
                    )
                    parts.append(
                        f'  <circle cx="{stub_cx}" cy="{by}" r="5" fill="{col}" opacity="0.95"/>'
                    )

                    # Collect badge info for each IP in this CIDR on this node
                    prefix_str = cidr.split("/")[1] if "/" in cidr else "24"
                    for ip in cidr_ips[cidr]:
                        ni_iface = next(
                            (ni.iface for ni in r.network_interfaces if ni.ip == ip),
                            ""
                        )
                        node_badges.setdefault(r.server_id, []).append(
                            (stub_cx, direction, ip, ni_iface or "", col, prefix_str)
                        )

    # ── ES cluster badge ──────────────────────────────────────────────────────
    if 4 in layers:
        es_names: list[str] = []
        for r in layers[4]:
            if r.es_cluster_name and r.es_cluster_name not in es_names:
                es_names.append(r.es_cluster_name)
        if es_names:
            al_i = active_layers.index(4)
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

    # ── Connection overlay placeholder (behind node cards) ────────────────────
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
        node_top    = cy - NODE_H // 2
        node_bottom = cy + NODE_H // 2

        border_color = "#2d4a6b" if r.success else ("#e67e22" if is_disc else "#c0392b")
        border_width = "2" if is_disc else ("1.5" if r.success else "2")

        # Body center (left of role strip)
        body_cx = x + BODY_W // 2

        # 1. Card background (full width)
        parts.append(
            f'  <rect x="{x}" y="{y}" width="{NODE_W}" height="{NODE_H}" '
            f'rx="10" fill="#162032" stroke="{border_color}" stroke-width="{border_width}"/>'
        )

        # 2. Right role strip — colored vertical band (rounded right side only)
        strip_x = x + BODY_W
        parts.append(
            f'  <rect x="{strip_x}" y="{y+1}" width="{ROLE_STRIP_W-1}" height="{NODE_H-2}" '
            f'rx="9" fill="{color}" fill-opacity="0.88"/>'
        )
        # Left edge of strip (square to merge with body)
        parts.append(
            f'  <rect x="{strip_x}" y="{y+1}" width="12" height="{NODE_H-2}" '
            f'fill="{color}" fill-opacity="0.88"/>'
        )
        # Thin left border line between body and strip
        parts.append(
            f'  <line x1="{strip_x}" y1="{y+4}" x2="{strip_x}" y2="{y+NODE_H-4}" '
            f'stroke="{color}" stroke-width="1.5" opacity="0.6"/>'
        )

        strip_cx = strip_x + ROLE_STRIP_W // 2  # center of strip

        # 2a. Status icon at top of strip
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

        # 2b. Role abbreviations stacked in strip (above the centered buttons)
        role_labels = [ROLE_SHORT.get(rd.role, rd.role) for rd in r.roles] if r.roles else ["?"]
        BTN_W  = ROLE_STRIP_W - 10
        BTN_H  = 13
        # Buttons centered vertically in strip
        det_by  = y + NODE_H // 2 - BTN_H - 2
        json_by = y + NODE_H // 2 + 2
        det_bx  = strip_x + 5
        # Labels fill the space between status icon and buttons
        max_roles = max(1, (det_by - (y + 28)) // 14)
        for ri, rl in enumerate(role_labels[:max_roles]):
            parts.append(
                f'  <text x="{strip_cx}" y="{y+30+ri*14}" text-anchor="middle" '
                f'fill="#ffffff" font-size="9" font-weight="bold" font-family="{FONT}">'
                f'{_esc(rl)}</text>'
            )

        # 2c. Details + JSON buttons — vertically centered in strip
        parts.append(
            f'  <a href="#" onclick="svgNodeDetails(event,&quot;{_esc(r.server_id)}&quot;)" style="cursor:pointer">'
        )
        parts.append(
            f'  <rect x="{det_bx}" y="{det_by}" width="{BTN_W}" height="{BTN_H}" rx="3" '
            f'fill="#1e3a5f" stroke="#2563eb" stroke-width="1" opacity="0.95"/>'
        )
        parts.append(
            f'  <text x="{strip_cx}" y="{det_by+10}" text-anchor="middle" '
            f'fill="#93c5fd" font-size="9" font-family="{FONT}">Details</text>'
        )
        parts.append('  </a>')

        if show_json:
            parts.append(
                f'  <a href="/api/audit/dump/{_esc(r.server_id)}" target="_blank"'
                f' onclick="event.stopPropagation()">'
            )
            parts.append(
                f'  <rect x="{det_bx}" y="{json_by}" width="{BTN_W}" height="{BTN_H}" rx="3" '
                f'fill="#162032" stroke="#475569" stroke-width="1" opacity="0.95"/>'
            )
            parts.append(
                f'  <text x="{strip_cx}" y="{json_by+10}" text-anchor="middle" '
                f'fill="#64748b" font-size="9" font-family="{FONT}">JSON</text>'
            )
            parts.append('  </a>')

        # 3. Role icon (primary) in body, upper area
        icon_cy = y + NODE_H // 2 - 18
        parts.extend(_role_icon_svg(role, color, body_cx, icon_cy, scale=1.75))

        # 4. Server name — centered in body
        name_str = (r.server_name[:26] + "…") if len(r.server_name) > 26 else r.server_name
        name_y = icon_cy + 20
        parts.append(
            f'  <text x="{body_cx}" y="{name_y}" text-anchor="middle" '
            f'fill="#f1f5f9" font-size="12" font-weight="bold" font-family="{FONT}">'
            f'{_esc(name_str)}</text>'
        )

        # 5. Storage node capacity bar (centered in body, bottom area)
        sn_data = swarmctl_lookup.get(r.server_id)
        if sn_data is not None:
            try:
                _used_pct = 100 - int(sn_data.avail_pct.replace("%", "").strip())
            except (ValueError, AttributeError):
                _used_pct = 0
            bar_y   = y + NODE_H - 26
            bar_w   = BODY_W - 16
            filled  = int(bar_w * _used_pct / 100)
            bar_col = "#e74c3c" if _used_pct > 85 else ("#f39c12" if _used_pct > 70 else "#27ae60")
            parts.append(
                f'  <text x="{body_cx}" y="{bar_y - 3}" text-anchor="middle" '
                f'fill="#bdc3c7" font-size="8" font-family="{FONT}">'
                f'{_esc(sn_data.used)}/{_esc(sn_data.max)} · {_esc(sn_data.streams)} str</text>'
            )
            parts.append(f'  <rect x="{x+8}" y="{bar_y}" width="{bar_w}" height="6" rx="3" fill="#2c3e50"/>')
            if filled > 0:
                parts.append(f'  <rect x="{x+8}" y="{bar_y}" width="{filled}" height="6" rx="3" fill="{bar_col}"/>')

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

        # 7. IP badges — 4px inside tile edge, badge color = wire color
        for badge_scx, badge_dir, badge_ip, badge_iface, badge_col, badge_prefix in node_badges.get(r.server_id, []):
            ip_label = _ip_suffix_for_mask(badge_ip, badge_prefix)
            if badge_dir == "up":
                badge_y = node_top + BADGE_PAD
                wire_y1, wire_y2 = node_top, badge_y
            else:
                badge_y = node_bottom - BADGE_H_S - BADGE_PAD
                wire_y1, wire_y2 = node_bottom, badge_y + BADGE_H_S
            # Short inner wire from tile edge to badge
            parts.append(
                f'  <line x1="{badge_scx}" y1="{wire_y1}" x2="{badge_scx}" y2="{wire_y2}" '
                f'stroke="{badge_col}" stroke-width="1.5" opacity="0.9"/>'
            )
            # Badge rect
            badge_w = max(28, len(ip_label) * 5 + 10)
            bx = badge_scx - badge_w // 2
            parts.append(
                f'  <rect x="{bx}" y="{badge_y}" width="{badge_w}" height="{BADGE_H_S}" '
                f'rx="3" fill="#0d1628" stroke="{badge_col}" stroke-width="1" opacity="0.95"/>'
            )
            parts.append(
                f'  <text x="{badge_scx}" y="{badge_y+6}" text-anchor="middle" '
                f'fill="{badge_col}" font-size="7" font-weight="bold" font-family="{FONT}">'
                f'{_esc(ip_label)}</text>'
            )
            if badge_iface:
                parts.append(
                    f'  <text x="{badge_scx}" y="{badge_y+13}" text-anchor="middle" '
                    f'fill="#94a3b8" font-size="6" font-family="{FONT}">{_esc(badge_iface)}</text>'
                )

        # 8. Transparent click overlay (body only — strip has its own handlers)
        parts.append(
            f'  <rect x="{x}" y="{y}" width="{BODY_W}" height="{NODE_H}" '
            f'fill="none" style="cursor:pointer" '
            f'onclick="svgNodeClick(event,&quot;{_esc(r.server_id)}&quot;)"/>'
        )

    # ── Legend ────────────────────────────────────────────────────────────────
    if subnet_colors:
        nlw = 200
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

        # Live TCP connections
        live_conns = [
            {"dst": c.remote_addr, "port": c.remote_port,
             "proc": (c.process or "")[:20], "cfg": False}
            for c in r.connections
            if c.remote_addr not in ("", "0.0.0.0", "*")
        ]

        # Config-inferred connections (role-semantic, not dependent on live TCP state)
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
    # syslog (UDP 514) + NTP (UDP 123): every non-server node → syslog/NTP server
    # DHCP (UDP 67) + PXE/TFTP (UDP 69): storage nodes only → DHCP/PXE server
    svc_ips: dict[str, list[str]] = {"syslog": [], "ntp": [], "dhcp": [], "pxe": []}
    for r2 in all_nodes_flat:
        if r2.server_id not in positions:
            continue
        if r2.is_syslog_server:
            svc_ips["syslog"].append(r2.server_ip)
        if r2.is_ntp_server:
            svc_ips["ntp"].append(r2.server_ip)
        if r2.is_dhcp_server:
            svc_ips["dhcp"].append(r2.server_ip)
        if r2.is_pxe_server:
            svc_ips["pxe"].append(r2.server_ip)
    # Fallback: SCS-role node assumed to provide all four services when not detected
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
        m = node_meta[r2.server_id]
        r2_ips = set(m["ips"])
        primary = m["role"]
        for _svc, _server_ips in svc_ips.items():
            for _sip in _server_ips:
                if _sip in r2_ips:
                    continue  # skip the server itself
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
