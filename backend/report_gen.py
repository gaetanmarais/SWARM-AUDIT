# Version: 1.2.0
# Date:    2026-06-21
# Notes:   Add connections section + raw JSON collapsible to server cards in static export.

from __future__ import annotations
import html
import json
from datetime import datetime, timezone
from typing import Optional

from models import AuditResult, AnalysisResult

SEVERITY_COLOR = {
    "CRITICAL": ("#fee2e2", "#991b1b", "#dc2626"),   # bg, text, badge-bg
    "WARNING":  ("#fef3c7", "#92400e", "#d97706"),
    "INFO":     ("#dbeafe", "#1e40af", "#3b82f6"),
    "OK":       ("#dcfce7", "#166534", "#16a34a"),
}

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;font-size:14px}
a{color:#60a5fa}
h1{font-size:1.25rem;font-weight:700}
h2{font-size:1rem;font-weight:600;margin-bottom:.5rem}
h3{font-size:.875rem;font-weight:600;margin-bottom:.25rem}

/* ── Layout ── */
#header{background:#1e293b;border-bottom:1px solid #334155;padding:.75rem 1.5rem;
        display:flex;align-items:center;justify-content:space-between;gap:1rem;position:sticky;top:0;z-index:100}
#header .meta{font-size:.75rem;color:#94a3b8}
#tabs{display:flex;gap:0;border-bottom:1px solid #334155;background:#1e293b;position:sticky;top:57px;z-index:99}
.tab{padding:.6rem 1.5rem;cursor:pointer;color:#94a3b8;border-bottom:2px solid transparent;font-size:.8rem;font-weight:500;letter-spacing:.04em;text-transform:uppercase}
.tab:hover{color:#e2e8f0;background:#0f172a}
.tab.active{color:#38bdf8;border-bottom-color:#38bdf8}
.panel{display:none;padding:1.25rem 1.5rem}
.panel.active{display:block}

/* ── Diagram ── */
#diagram-wrap{background:#1e293b;border:1px solid #334155;border-radius:.5rem;overflow:auto;padding:1rem;
              cursor:grab;max-height:calc(100vh - 160px)}
#diagram-wrap svg{display:block;width:100%;height:auto}

/* ── Audit table ── */
.server-card{background:#1e293b;border:1px solid #334155;border-radius:.5rem;margin-bottom:.75rem;overflow:hidden}
.server-card summary{padding:.75rem 1rem;cursor:pointer;display:flex;align-items:center;gap:.75rem;list-style:none;user-select:none}
.server-card summary::-webkit-details-marker{display:none}
.server-card summary:hover{background:#0f172a}
.server-card .server-name{font-weight:600;font-size:.875rem}
.server-card .server-ip{color:#94a3b8;font-size:.75rem}
.role-badge{background:#1d4ed8;color:#bfdbfe;padding:.1rem .5rem;border-radius:9999px;font-size:.7rem;font-weight:600}
.server-body{padding:1rem;border-top:1px solid #334155;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem}
.server-section h3{color:#94a3b8;font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.4rem}
.kv{display:flex;justify-content:space-between;font-size:.78rem;padding:.1rem 0;border-bottom:1px solid #0f172a}
.kv .k{color:#94a3b8}
.kv .v{color:#e2e8f0;text-align:right;max-width:60%;word-break:break-all}
.cfg-block{background:#0f172a;border-radius:.25rem;padding:.5rem;font-family:monospace;font-size:.7rem;
           white-space:pre-wrap;word-break:break-all;max-height:200px;overflow-y:auto;margin-top:.25rem;color:#a5f3fc}
.log-block{background:#0f172a;border-radius:.25rem;padding:.5rem;font-family:monospace;font-size:.7rem;
           white-space:pre-wrap;max-height:160px;overflow-y:auto;color:#d1fae5}

/* ── Analysis ── */
.role-section{margin-bottom:1.5rem}
.role-header{background:#1e293b;border:1px solid #334155;border-radius:.5rem .5rem 0 0;
             padding:.75rem 1rem;display:flex;align-items:center;gap:.75rem}
.role-title{font-size:.95rem;font-weight:700;color:#38bdf8}
.role-summary{font-size:.78rem;color:#94a3b8;margin-top:.1rem}
.findings-list{border:1px solid #334155;border-top:none;border-radius:0 0 .5rem .5rem;overflow:hidden}
.finding{border-top:1px solid #1e293b;padding:.75rem 1rem}
.finding:first-child{border-top:none}
.sev-badge{display:inline-block;padding:.1rem .5rem;border-radius:9999px;font-size:.65rem;font-weight:700;margin-right:.5rem}
.finding-title{font-size:.82rem;font-weight:600;display:inline}
.finding-detail{font-size:.78rem;color:#cbd5e1;margin:.4rem 0}
.finding-meta{display:grid;grid-template-columns:1fr 1fr;gap:.5rem;margin-top:.5rem}
.meta-block{background:#0f172a;border-radius:.25rem;padding:.5rem}
.meta-block .label{font-size:.65rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em;margin-bottom:.2rem}
.meta-block .value{font-family:monospace;font-size:.72rem;color:#a5f3fc;white-space:pre-wrap;word-break:break-all}
.meta-block.reco .value{font-family:inherit;color:#fde68a}
.meta-block.doc .value a{color:#60a5fa}
.servers-tag{font-size:.7rem;color:#64748b;margin-top:.4rem}
.cross-section{margin-top:1.5rem;background:#1e293b;border:1px solid #334155;border-radius:.5rem;overflow:hidden}
.cross-header{padding:.75rem 1rem;font-size:.875rem;font-weight:700;color:#f0abfc;border-bottom:1px solid #334155}
.log-findings-section{margin-top:.5rem;background:#0f172a;border-radius:.25rem;padding:.5rem}
.log-findings-label{font-size:.65rem;color:#4ade80;text-transform:uppercase;letter-spacing:.06em;margin-bottom:.3rem}
"""

JS = """
function showTab(id) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  document.getElementById('panel-' + id).classList.add('active');
}
// Diagram pan/zoom
(function() {
  const wrap = document.getElementById('diagram-wrap');
  if (!wrap) return;
  let drag = false, sx = 0, sy = 0, ox = 0, oy = 0;
  wrap.addEventListener('mousedown', e => { drag = true; sx = e.clientX - ox; sy = e.clientY - oy; wrap.style.cursor='grabbing'; });
  window.addEventListener('mousemove', e => { if (!drag) return; ox = e.clientX - sx; oy = e.clientY - sy; });
  window.addEventListener('mouseup', () => { drag = false; wrap.style.cursor='grab'; });
})();
"""

def _sev_badge(sev: str) -> str:
    bg, fg, _ = SEVERITY_COLOR.get(sev, ("#334155", "#e2e8f0", "#64748b"))
    return f'<span class="sev-badge" style="background:{bg};color:{fg}">{html.escape(sev)}</span>'


def _finding_html(f: dict) -> str:
    sev = f.get("severity", "INFO")
    _, _, badge_bg = SEVERITY_COLOR.get(sev, ("#334155", "#e2e8f0", "#334155"))
    bg, fg, _ = SEVERITY_COLOR.get(sev, ("#1e293b", "#e2e8f0", "#334155"))
    title = html.escape(f.get("title", ""))
    detail = html.escape(f.get("detail", ""))
    cur = html.escape(f.get("current_value", ""))
    fix = html.escape(f.get("corrected_config", ""))
    reco = html.escape(f.get("recommendation", ""))
    doc = f.get("doc_reference", "")
    servers = ", ".join(f.get("servers", []))

    meta_parts = ""
    if cur:
        meta_parts += f'<div class="meta-block"><div class="label">Current value</div><div class="value">{cur}</div></div>'
    if fix:
        meta_parts += f'<div class="meta-block"><div class="label">Corrected config</div><div class="value">{fix}</div></div>'
    if reco:
        meta_parts += f'<div class="meta-block reco" style="grid-column:1/-1"><div class="label">Recommendation</div><div class="value">{reco}</div></div>'
    if doc:
        doc_esc = html.escape(doc)
        # If it looks like a URL, wrap in <a>
        if doc.startswith("http"):
            doc_html = f'<a href="{doc_esc}" target="_blank" rel="noopener">{doc_esc}</a>'
        else:
            doc_html = doc_esc
        meta_parts += f'<div class="meta-block doc" style="grid-column:1/-1"><div class="label">Documentation</div><div class="value">{doc_html}</div></div>'

    return f"""<div class="finding" style="background:{bg}10">
  {_sev_badge(sev)}<span class="finding-title">{title}</span>
  {f'<div class="finding-detail">{detail}</div>' if detail else ''}
  {f'<div class="finding-meta">{meta_parts}</div>' if meta_parts else ''}
  {f'<div class="servers-tag">Servers: {html.escape(servers)}</div>' if servers else ''}
</div>"""


def _server_card(r: dict) -> str:
    name = html.escape(r.get("server_name", r.get("server_id", "?")))
    ip = html.escape(r.get("server_ip", ""))
    roles = r.get("roles", [])
    role_badges = " ".join(f'<span class="role-badge">{html.escape(rd.get("role","?"))}</span>' for rd in roles)
    ok_icon = "✓" if r.get("success") else "✗"
    ok_color = "#4ade80" if r.get("success") else "#f87171"

    # Specs section
    cpu = r.get("cpu", {})
    ram = r.get("ram", {})
    specs_rows = ""
    if cpu:
        specs_rows += f'<div class="kv"><span class="k">CPU</span><span class="v">{html.escape(str(cpu.get("count","?")))}× {html.escape(str(cpu.get("model","?"))[:50])}</span></div>'
    if ram:
        specs_rows += f'<div class="kv"><span class="k">RAM</span><span class="v">{ram.get("total_mb","?")} MB (free: {ram.get("free_mb","?")} MB)</span></div>'
    os_str = r.get("os", "")
    if os_str:
        specs_rows += f'<div class="kv"><span class="k">OS</span><span class="v">{html.escape(os_str)}</span></div>'
    kernel = r.get("kernel", "")
    if kernel:
        specs_rows += f'<div class="kv"><span class="k">Kernel</span><span class="v">{html.escape(kernel)}</span></div>'
    uptime = r.get("uptime_sec")
    if uptime:
        d, rem = divmod(int(uptime), 86400); h, rem = divmod(rem, 3600); m = rem // 60
        specs_rows += f'<div class="kv"><span class="k">Uptime</span><span class="v">{d}d {h}h {m}m</span></div>'

    # Disks
    disks = r.get("disks", [])
    disk_rows = "".join(
        f'<div class="kv"><span class="k">{html.escape(d.get("mount","?"))}</span>'
        f'<span class="v">{d.get("size_gb","?")}GB — {d.get("used_pct","?")} used</span></div>'
        for d in disks[:8]
    )

    # Ports
    ports = r.get("listen_ports", [])
    ports_str = ", ".join(html.escape(p.get("port", "")) for p in ports[:30])

    # Connections
    conns = r.get("connections", [])
    conn_rows = ""
    for c in conns[:60]:
        src = html.escape(c.get("local", ""))
        dst = html.escape(c.get("remote", ""))
        proc = html.escape(c.get("process", ""))
        state = html.escape(c.get("state", ""))
        conn_rows += (
            f'<div class="kv">'
            f'<span class="k" style="font-family:monospace">{src} → {dst}</span>'
            f'<span class="v">{proc} {state}</span>'
            f'</div>'
        )

    # Config files
    cfg_blocks = ""
    for path, content in list(r.get("config_contents", {}).items())[:6]:
        cfg_blocks += f'<h3>{html.escape(path)}</h3><div class="cfg-block">{html.escape(content[:1500])}</div>'

    # Logs
    log_blocks = ""
    for role_key, log_text in r.get("logs", {}).items():
        if log_text:
            log_blocks += f'<h3>{html.escape(role_key)} logs</h3><div class="log-block">{html.escape(log_text[:1500])}</div>'

    # Raw JSON — stripped of bulky log/config content for readability
    raw_keys = ["server_id","server_name","server_ip","hostname","os","kernel","uptime_sec",
                "cpu","ram","disks","roles","listen_ports","connections","network_interfaces",
                "gw_cluster_ips","gw_es_ips","gw_lcs_ips","haproxy_backends","haproxy_vips",
                "swarm_cluster_summary","discovered_storage_nodes","es_cluster_name",
                "discovered_es_nodes","es_seed_hosts","is_syslog_server","is_ntp_server",
                "is_dhcp_server","is_pxe_server","installed_packages"]
    raw_dict = {k: r[k] for k in raw_keys if k in r}
    raw_json = html.escape(json.dumps(raw_dict, indent=2, default=str))

    return f"""<details class="server-card">
  <summary>
    <span style="color:{ok_color};font-weight:700">{ok_icon}</span>
    <span class="server-name">{name}</span>
    <span class="server-ip">{ip}</span>
    {role_badges}
  </summary>
  <div class="server-body">
    {'<div class="server-section"><h3>Specs</h3>' + specs_rows + '</div>' if specs_rows else ''}
    {'<div class="server-section"><h3>Disks</h3>' + disk_rows + '</div>' if disk_rows else ''}
    {'<div class="server-section"><h3>Listen ports</h3><div class="kv"><span class="v">' + ports_str + '</span></div></div>' if ports_str else ''}
    {'<div class="server-section" style="grid-column:1/-1"><h3>Active connections</h3>' + conn_rows + '</div>' if conn_rows else ''}
    {'<div class="server-section" style="grid-column:1/-1"><h3>Config files</h3>' + cfg_blocks + '</div>' if cfg_blocks else ''}
    {'<div class="server-section" style="grid-column:1/-1"><h3>Application logs (24h)</h3>' + log_blocks + '</div>' if log_blocks else ''}
    <div class="server-section" style="grid-column:1/-1">
      <details>
        <summary style="cursor:pointer;color:#64748b;font-size:.75rem;padding:.25rem 0">Raw JSON</summary>
        <div class="cfg-block" style="max-height:400px">{raw_json}</div>
      </details>
    </div>
  </div>
</details>"""


def _role_section_html(module: dict) -> str:
    role = html.escape(module.get("role", "?"))
    servers = ", ".join(html.escape(s) for s in module.get("servers", []))
    summary = html.escape(module.get("summary", ""))
    cfg_findings = module.get("config_findings", [])
    log_findings = module.get("log_findings", [])

    # Count by severity
    counts = {}
    for f in cfg_findings + log_findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1
    badges = "".join(
        f'<span class="sev-badge" style="background:{SEVERITY_COLOR[s][0]};color:{SEVERITY_COLOR[s][1]}">'
        f'{counts[s]} {s}</span>'
        for s in ["CRITICAL", "WARNING", "INFO", "OK"] if s in counts
    )

    cfg_html = "".join(_finding_html(f) for f in cfg_findings)
    log_html = ""
    if log_findings:
        inner = "".join(_finding_html(f) for f in log_findings)
        log_html = f'<div class="log-findings-section"><div class="log-findings-label">Log findings</div>{inner}</div>'

    return f"""<div class="role-section">
  <div class="role-header">
    <div>
      <div class="role-title">{role}</div>
      <div class="role-summary">{servers} — {summary}</div>
    </div>
    <div style="margin-left:auto;display:flex;gap:.35rem;flex-wrap:wrap">{badges}</div>
  </div>
  <div class="findings-list">
    {cfg_html}
    {log_html}
  </div>
</div>"""


def generate_report_html(
    results: list[AuditResult],
    svg_content: str,
    analysis: Optional[AnalysisResult],
    generated_at: Optional[str] = None,
    cluster_name: str = "swarm",
) -> str:
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    results_dicts = [r.model_dump() for r in results]
    analysis_dict = analysis.model_dump() if analysis else {}

    # ── Page: Diagram ──────────────────────────────────────────────────────────
    diagram_html = f'<div id="diagram-wrap">{svg_content}</div>' if svg_content else \
        '<p style="color:#64748b;padding:2rem">No diagram available.</p>'

    # ── Page: Audit ───────────────────────────────────────────────────────────
    if results_dicts:
        audit_html = "".join(_server_card(r) for r in results_dicts)
    else:
        audit_html = '<p style="color:#64748b;padding:2rem">No audit data available.</p>'

    # ── Page: Analysis ────────────────────────────────────────────────────────
    modules = analysis_dict.get("modules", [])
    cross = analysis_dict.get("cross_correlations", [])
    if modules:
        analysis_html = "".join(_role_section_html(m) for m in modules)
        if cross:
            cross_items = "".join(_finding_html(f) for f in cross)
            analysis_html += f'<div class="cross-section"><div class="cross-header">Cross-component correlations</div>{cross_items}</div>'
    else:
        analysis_html = '<p style="color:#64748b;padding:2rem">No analysis available.</p>'

    n_servers = len(results_dicts)
    n_critical = sum(
        1 for m in modules
        for f in m.get("config_findings", []) + m.get("log_findings", [])
        if f.get("severity") == "CRITICAL"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARCIS-SWARM — {html.escape(cluster_name)} — {generated_at}</title>
<style>{CSS}</style>
</head>
<body>

<div id="header">
  <div>
    <h1>ARCIS-SWARM — {html.escape(cluster_name)}</h1>
    <div class="meta">{n_servers} servers · {n_critical} critical findings · Generated {generated_at}</div>
  </div>
  <div style="font-size:.7rem;color:#475569">Static report — read only</div>
</div>

<div id="tabs">
  <div class="tab active" id="tab-diagram" onclick="showTab('diagram')">Diagram</div>
  <div class="tab" id="tab-audit" onclick="showTab('audit')">Audit ({n_servers})</div>
  <div class="tab" id="tab-analysis" onclick="showTab('analysis')">Analysis{' (' + str(n_critical) + ' critical)' if n_critical else ''}</div>
</div>

<div class="panel active" id="panel-diagram">
  {diagram_html}
</div>

<div class="panel" id="panel-audit">
  {audit_html}
</div>

<div class="panel" id="panel-analysis">
  {analysis_html}
</div>

<script>{JS}</script>
</body>
</html>"""
