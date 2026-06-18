# Version: 2.0.0
# Date:    2026-06-18
# Notes:   Rewrite for per-node SNMP healthreport format (swarmctl -d <node_ip> -Q healthreport)
#          Parses columnar SNMP tables (Volumes Table, Announcements, Drive Table, NIC Table)

from __future__ import annotations
import html as _html
from datetime import datetime, timezone


def _esc(s: object) -> str:
    return _html.escape(str(s)) if s is not None else ""


def _bar(pct: float, width: int = 120) -> str:
    pct = max(0.0, min(100.0, pct))
    color = "#ef4444" if pct > 85 else "#f59e0b" if pct > 70 else "#22c55e"
    fill = int(width * pct / 100)
    return (
        f'<div style="display:inline-block;width:{width}px;height:10px;'
        f'background:#1e293b;border-radius:4px;vertical-align:middle;">'
        f'<div style="width:{fill}px;height:10px;background:{color};border-radius:4px;"></div>'
        f'</div>&nbsp;<span style="color:{color};font-size:11px;">{pct:.1f}%</span>'
    )


def _col_table(table: dict, col_key: str) -> list[dict]:
    """Convert SNMP columnar dict {col_name: [v0, v1, ...]} into list of row dicts."""
    if not isinstance(table, dict):
        return []
    lengths = [len(v) for v in table.values() if isinstance(v, list)]
    if not lengths:
        return []
    n = max(lengths)
    rows = []
    for i in range(n):
        row = {}
        for k, vals in table.items():
            if isinstance(vals, list):
                row[k] = vals[i] if i < len(vals) else None
            else:
                row[k] = vals
        rows.append(row)
    return rows


def _parse_node(hr: dict, node_ip: str) -> dict:
    """Normalize per-node SNMP healthreport JSON into a flat display dict."""
    objs   = hr.get("SNMP objects", {}) or {}
    tables = hr.get("SNMP tables",  {}) or {}
    nic    = hr.get("NIC",          {}) or {}
    cluster_raw = hr.get("Cluster", {}) or {}

    # Chassis memory
    mem_total_mb = int(objs.get("Chassis Memory Total (MB)") or 0)
    mem_free_mb  = int(objs.get("Chassis Memory Free (MB)")  or 0)
    mem_avail_mb = int(objs.get("Chassis Memory Available (MB)") or 0)
    arena_mb     = int(objs.get("Chassis Arena (MB)")     or 0)
    headroom_mb  = int(objs.get("Chassis Headroom (MB)")  or 0)
    mem_used_pct = ((mem_total_mb - mem_free_mb) / mem_total_mb * 100) if mem_total_mb else 0

    # Version
    version  = str(objs.get("CAStor version")  or objs.get("CAStor revision") or "—")
    chassis_id = str(objs.get("Chassis Id") or "")

    # HP cycle (from SNMP objects — totals)
    hp_exam_ongoing = int(objs.get("HP ongoing cycle: Streams examined") or 0)
    hp_proc_ongoing = int(objs.get("HP ongoing cycle: Streams processed") or 0)
    hp_exam_last    = int(objs.get("HP last cycle: Streams examined")    or 0)
    hp_proc_last    = int(objs.get("HP last cycle: Streams processed")   or 0)
    hp_pct_ongoing  = (hp_proc_ongoing / hp_exam_ongoing * 100) if hp_exam_ongoing else 0.0

    # Volumes Table (columnar)
    vol_rows = _col_table(tables.get("Volumes Table", {}), "Name")
    # Keep only non-retired volumes for summary
    active_vols = [r for r in vol_rows if str(r.get("State") or "").lower() not in ("retired",)]

    # Drive Table
    dt = tables.get("Drive Table", {}) or {}
    drive_ids = dt.get("drive bus id", []) if isinstance(dt, dict) else []
    drive_count = len(drive_ids) if isinstance(drive_ids, list) else 0

    # Announcements Table
    ann_table = tables.get("Announcements Table", {}) or {}
    ann_rows  = _col_table(ann_table, "Index")

    # NIC Table
    nic_table_rows = _col_table(tables.get("NIC Table", {}), "NIC device")

    # Cluster summary from SNMP objects
    cl_state        = str(objs.get("Cluster: State") or cluster_raw.get("status") or "—")
    cl_total_tb     = round(int(objs.get("Cluster: Total GBytes Licensed Capacity") or cluster_raw.get("physicalSpace") or 0) / 1024, 1)
    cl_avail_tb     = round(int(objs.get("Cluster: Total GBytes available") or 0) / 1024, 1)
    cl_objects      = int(objs.get("Cluster: Total Logical Objects") or 0)
    cl_name         = str(cluster_raw.get("name") or "")
    cl_nodes        = int(cluster_raw.get("nodeCount") or 0)

    return {
        "ip":            node_ip,
        "version":       version,
        "chassis_id":    chassis_id,
        "mem_total_mb":  mem_total_mb,
        "mem_free_mb":   mem_free_mb,
        "mem_avail_mb":  mem_avail_mb,
        "arena_mb":      arena_mb,
        "headroom_mb":   headroom_mb,
        "mem_used_pct":  mem_used_pct,
        "hp_pct_ongoing":hp_pct_ongoing,
        "hp_exam_ongoing":hp_exam_ongoing,
        "hp_proc_ongoing":hp_proc_ongoing,
        "hp_exam_last":  hp_exam_last,
        "hp_proc_last":  hp_proc_last,
        "vol_rows":      vol_rows,
        "active_vols":   active_vols,
        "drive_count":   drive_count,
        "drive_ids":     drive_ids if isinstance(drive_ids, list) else [],
        "ann_rows":      ann_rows,
        "nic_linespeed": str(nic.get("Linespeed") or "—"),
        "nic_mtu":       str(nic.get("MTU") or "—"),
        "nic_table":     nic_table_rows,
        "cl_state":      cl_state,
        "cl_total_tb":   cl_total_tb,
        "cl_avail_tb":   cl_avail_tb,
        "cl_objects":    cl_objects,
        "cl_name":       cl_name,
        "cl_nodes":      cl_nodes,
    }


def _node_row_html(n: dict, idx: int) -> str:
    bg = "#0f172a" if idx % 2 == 0 else "#0c1526"
    cl_col = "#22c55e" if n["cl_state"].lower() == "ok" else "#f59e0b"
    ann_col = "#f59e0b" if n["ann_rows"] else "#475569"
    vol_summary = ", ".join(
        f'{r.get("Used streams", 0)} str / {round(int(r.get("Capacity space (MB)") or 0)/1024, 0):.0f}GB'
        for r in n["active_vols"][:3]
    ) or "—"

    return f"""
    <tr style="background:{bg};border-bottom:1px solid #1e293b;">
      <td style="padding:8px 10px;font-family:monospace;color:#7dd3fc;">{_esc(n["ip"])}</td>
      <td style="padding:8px 10px;color:#a5f3fc;font-size:11px;">{_esc(n["version"])}</td>
      <td style="padding:8px 10px;text-align:center;">
        {_bar(n["mem_used_pct"], 90)}<br>
        <span style="color:#64748b;font-size:10px;">
          {n["mem_total_mb"]//1024} GB total · {n["mem_avail_mb"]//1024} GB avail
        </span>
      </td>
      <td style="padding:8px 10px;color:#a5f3fc;font-size:11px;">{_esc(vol_summary)}</td>
      <td style="padding:8px 10px;text-align:center;color:#94a3b8;">{n["drive_count"]}</td>
      <td style="padding:8px 10px;">
        {_bar(n["hp_pct_ongoing"], 80)}<br>
        <span style="color:#64748b;font-size:10px;">{n["hp_proc_ongoing"]:,} / {n["hp_exam_ongoing"]:,}</span>
      </td>
      <td style="padding:8px 10px;text-align:center;color:{cl_col};">{_esc(n["cl_state"].upper())}</td>
      <td style="padding:8px 10px;text-align:center;color:{ann_col};">
        <a href="#node-{idx}" style="color:{ann_col};text-decoration:none;">
          {len(n["ann_rows"]) if n["ann_rows"] else "—"}
        </a>
      </td>
    </tr>"""


def _node_detail_html(n: dict, idx: int, node_data: dict) -> str:
    # Volumes table
    vol_html = ""
    if n["vol_rows"]:
        rows_h = ""
        for r in n["vol_rows"]:
            cap_mb  = int(r.get("Capacity space (MB)") or 0)
            used_mb = int(r.get("Used space (MB)") or 0)
            free_mb = int(r.get("Free space (MB)") or 0)
            strms   = int(r.get("Used streams") or 0)
            state   = str(r.get("State") or "—")
            name    = str(r.get("Name") or "—")
            pct     = (used_mb / cap_mb * 100) if cap_mb else 0
            state_col = "#ef4444" if state.lower() == "retired" else "#22c55e" if state.lower() == "ok" else "#f59e0b"
            rows_h += f"""<tr style="border-bottom:1px solid #0f172a;">
              <td style="padding:4px 8px;color:#7dd3fc;font-family:monospace;font-size:11px;">{_esc(name)}</td>
              <td style="padding:4px 8px;color:{state_col};font-size:11px;">{_esc(state)}</td>
              <td style="padding:4px 8px;color:#94a3b8;font-size:11px;">{cap_mb//1024} GB</td>
              <td style="padding:4px 8px;">{_bar(pct, 70)}</td>
              <td style="padding:4px 8px;text-align:right;color:#a5f3fc;font-size:11px;">{strms:,}</td>
            </tr>"""
        vol_html = f"""<table style="border-collapse:collapse;width:100%;font-size:12px;">
          <thead><tr style="border-bottom:1px solid #334155;">
            <th style="padding:4px 8px;color:#475569;font-weight:400;text-align:left;">Volume</th>
            <th style="padding:4px 8px;color:#475569;font-weight:400;text-align:left;">State</th>
            <th style="padding:4px 8px;color:#475569;font-weight:400;text-align:left;">Capacity</th>
            <th style="padding:4px 8px;color:#475569;font-weight:400;text-align:left;">Usage</th>
            <th style="padding:4px 8px;color:#475569;font-weight:400;text-align:right;">Streams</th>
          </tr></thead>
          <tbody>{rows_h}</tbody>
        </table>"""
    else:
        vol_html = '<p style="color:#475569;font-style:italic;font-size:12px;">No volume data</p>'

    # Drive table
    drive_html = ""
    if n["drive_ids"]:
        drive_cells = "".join(
            f'<span style="display:inline-block;background:#1e293b;border-radius:4px;'
            f'padding:2px 8px;margin:2px;font-family:monospace;color:#94a3b8;font-size:11px;">'
            f'{_esc(str(did))}</span>'
            for did in n["drive_ids"]
        )
        drive_html = f'<div style="margin-top:4px;">{drive_cells}</div>'
    else:
        drive_html = '<p style="color:#475569;font-style:italic;font-size:12px;">No drive data</p>'

    # NIC table
    nic_html = ""
    if n["nic_table"]:
        nic_rows = ""
        for r in n["nic_table"]:
            dev    = str(r.get("NIC device") or "—")
            driver = str(r.get("NIC driver") or "—")
            speed  = str(r.get("NIC speed")  or r.get("Linespeed") or "—")
            nic_rows += (
                f'<tr style="border-bottom:1px solid #0f172a;">'
                f'<td style="padding:3px 8px;color:#7dd3fc;font-family:monospace;font-size:11px;">{_esc(dev)}</td>'
                f'<td style="padding:3px 8px;color:#94a3b8;font-size:11px;">{_esc(driver)}</td>'
                f'<td style="padding:3px 8px;color:#a5f3fc;font-size:11px;">{_esc(speed)}</td>'
                f'</tr>'
            )
        nic_html = f"""<table style="border-collapse:collapse;font-size:12px;">
          <thead><tr style="border-bottom:1px solid #334155;">
            <th style="padding:3px 8px;color:#475569;font-weight:400;text-align:left;">NIC</th>
            <th style="padding:3px 8px;color:#475569;font-weight:400;text-align:left;">Driver</th>
            <th style="padding:3px 8px;color:#475569;font-weight:400;text-align:left;">Speed</th>
          </tr></thead>
          <tbody>{nic_rows}</tbody>
        </table>"""
    else:
        nic_html = f'<p style="color:#94a3b8;font-size:12px;">Link speed: {_esc(n["nic_linespeed"])} · MTU: {_esc(n["nic_mtu"])}</p>'

    # Announcements
    ann_html = ""
    if n["ann_rows"]:
        ann_items = ""
        for r in n["ann_rows"]:
            code = str(r.get("Code") or "")
            text = str(r.get("Text") or "")
            ann_items += (
                f'<div style="padding:4px 0;border-bottom:1px solid #1e293b;font-size:12px;">'
                f'<span style="color:#f59e0b;font-family:monospace;margin-right:10px;">{_esc(code)}</span>'
                f'<span style="color:#94a3b8;">{_esc(text[:120])}</span>'
                f'</div>'
            )
        ann_html = f"""<div style="grid-column:1/-1;">
          <h4 style="color:#f59e0b;font-size:12px;margin:0 0 6px;text-transform:uppercase;letter-spacing:.05em;">
            Announcements ({len(n["ann_rows"])})
          </h4>
          <div style="max-height:180px;overflow-y:auto;">{ann_items}</div>
        </div>"""

    # Swarm cluster info section
    cl_col = "#22c55e" if n["cl_state"].lower() == "ok" else "#f59e0b"
    swarm_info = f"""
    <h4 style="color:#60a5fa;font-size:12px;margin:0 0 8px;text-transform:uppercase;letter-spacing:.05em;">Swarm Cluster</h4>
    <table style="border-collapse:collapse;font-size:12px;">
      <tr><td style="color:#475569;padding:3px 12px 3px 0;">State</td>
          <td style="color:{cl_col};font-weight:600;">{_esc(n["cl_state"].upper())}</td></tr>
      <tr><td style="color:#475569;padding:3px 12px 3px 0;">Capacity</td>
          <td style="color:#e2e8f0;">{n["cl_total_tb"]} TB licensed · {n["cl_avail_tb"]} TB available</td></tr>
      <tr><td style="color:#475569;padding:3px 12px 3px 0;">Objects</td>
          <td style="color:#a5f3fc;">{n["cl_objects"]:,}</td></tr>
      {"<tr><td style='color:#475569;padding:3px 12px 3px 0;'>Nodes</td><td style='color:#e2e8f0;'>"+str(n["cl_nodes"])+"</td></tr>" if n["cl_nodes"] else ""}
    </table>"""

    return f"""
    <details id="node-{idx}" open style="margin-bottom:12px;background:#0f172a;border:1px solid #1e293b;border-radius:8px;">
      <summary style="padding:12px 16px;cursor:pointer;color:#7dd3fc;font-family:monospace;
                      font-size:13px;list-style:none;display:flex;align-items:center;gap:12px;">
        <span style="color:#334155;">&#9654;</span>
        <span>{_esc(n["ip"])}</span>
        <span style="color:#a5f3fc;font-size:11px;">v{_esc(n["version"])}</span>
        <span style="color:#475569;font-size:11px;margin-left:auto;">
          {n["drive_count"]} drives · {len(n["vol_rows"])} volumes
        </span>
      </summary>
      <div style="padding:16px;display:grid;grid-template-columns:1fr 1fr;gap:20px;">

        <!-- Chassis & Memory -->
        <div>
          <h4 style="color:#60a5fa;font-size:12px;margin:0 0 8px;text-transform:uppercase;letter-spacing:.05em;">Chassis</h4>
          <table style="border-collapse:collapse;font-size:12px;">
            <tr><td style="color:#475569;padding:3px 12px 3px 0;">Chassis ID</td>
                <td style="color:#94a3b8;font-family:monospace;font-size:10px;">{_esc(n["chassis_id"])}</td></tr>
            <tr><td style="color:#475569;padding:3px 12px 3px 0;">Memory</td>
                <td>{_bar(n["mem_used_pct"], 100)}
                  <span style="color:#64748b;font-size:10px;margin-left:6px;">
                    {n["mem_total_mb"]//1024} GB total · {n["mem_avail_mb"]//1024} GB avail · {n["mem_free_mb"]//1024} GB free
                  </span>
                </td></tr>
            <tr><td style="color:#475569;padding:3px 12px 3px 0;">Arena</td>
                <td style="color:#e2e8f0;">{n["arena_mb"]//1024} GB
                  <span style="color:#64748b;font-size:10px;margin-left:6px;">headroom {n["headroom_mb"]//1024} GB</span>
                </td></tr>
          </table>
        </div>

        <!-- HP Cycle -->
        <div>
          <h4 style="color:#60a5fa;font-size:12px;margin:0 0 8px;text-transform:uppercase;letter-spacing:.05em;">HP Cycle (ongoing)</h4>
          <table style="border-collapse:collapse;font-size:12px;">
            <tr><td style="color:#475569;padding:3px 12px 3px 0;">Progress</td>
                <td>{_bar(n["hp_pct_ongoing"], 120)}</td></tr>
            <tr><td style="color:#475569;padding:3px 12px 3px 0;">Processed</td>
                <td style="color:#e2e8f0;">{n["hp_proc_ongoing"]:,} / {n["hp_exam_ongoing"]:,} streams</td></tr>
            <tr><td style="color:#475569;padding:3px 12px 3px 0;">Last cycle</td>
                <td style="color:#94a3b8;">{n["hp_proc_last"]:,} / {n["hp_exam_last"]:,} streams</td></tr>
          </table>
        </div>

        <!-- Swarm cluster -->
        <div>{swarm_info}</div>

        <!-- NIC -->
        <div>
          <h4 style="color:#60a5fa;font-size:12px;margin:0 0 8px;text-transform:uppercase;letter-spacing:.05em;">Network</h4>
          {nic_html}
        </div>

        <!-- Drives (full width) -->
        <div style="grid-column:1/-1;">
          <h4 style="color:#60a5fa;font-size:12px;margin:0 0 8px;text-transform:uppercase;letter-spacing:.05em;">
            Drives ({n["drive_count"]})
          </h4>
          {drive_html}
        </div>

        <!-- Volumes (full width) -->
        <div style="grid-column:1/-1;">
          <h4 style="color:#60a5fa;font-size:12px;margin:0 0 8px;text-transform:uppercase;letter-spacing:.05em;">
            Volumes ({len(n["vol_rows"])})
          </h4>
          {vol_html}
        </div>

        {ann_html}
      </div>
    </details>"""


def generate_health_report_html(results: list) -> str:
    """
    Generate PhoneHome-style HTML from discovered_storage_nodes[].health_report
    (per-node SNMP JSON format from swarmctl -d <node_ip> -Q healthreport).
    Falls back to any AuditResult.health_report_json with old cluster+nodes format.
    """
    # Collect per-node healthreport data from discovered_storage_nodes
    nodes_parsed: list[dict] = []
    seen_ips: set[str] = set()

    for r in results:
        for sn in getattr(r, "discovered_storage_nodes", []) or []:
            hr = getattr(sn, "health_report", None)
            if not hr or sn.ip in seen_ips:
                continue
            seen_ips.add(sn.ip)
            try:
                nodes_parsed.append(_parse_node(hr, sn.ip))
            except Exception:
                pass

    if not nodes_parsed:
        return _no_data_page()

    # Cluster name from first node
    cl_name = nodes_parsed[0]["cl_name"] or "—"
    cl_state = nodes_parsed[0]["cl_state"]
    state_col = "#22c55e" if cl_state.lower() == "ok" else "#f59e0b"
    now_str = datetime.now(timezone.utc).strftime("%H:%M UTC, %A %d %B %Y")

    # Summary rows
    summary_rows = "".join(_node_row_html(n, i) for i, n in enumerate(nodes_parsed))

    # Detail sections
    detail_sections = "".join(
        _node_detail_html(n, i, {}) for i, n in enumerate(nodes_parsed)
    )

    # Totals
    total_drives = sum(n["drive_count"] for n in nodes_parsed)
    total_vols   = sum(len(n["vol_rows"]) for n in nodes_parsed)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ARCIS-SWARM — Health Report{" — "+cl_name if cl_name != "—" else ""}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: #0f0f1e;
    color: #e2e8f0;
    font-family: 'Courier New', monospace;
    font-size: 13px;
    line-height: 1.5;
    padding: 24px;
  }}
  h1, h2, h3, h4 {{ font-family: 'Courier New', monospace; }}
  table {{ border-collapse: collapse; }}
  a {{ color: inherit; }}
  details > summary::-webkit-details-marker {{ display: none; }}
  .section-title {{
    font-size: 11px; text-transform: uppercase; letter-spacing: .08em;
    color: #475569; margin-bottom: 12px; padding-bottom: 6px;
    border-bottom: 1px solid #1e293b;
  }}
</style>
</head>
<body>

<div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:28px;">
  <div>
    <div style="color:#3b82f6;font-size:10px;letter-spacing:.15em;text-transform:uppercase;margin-bottom:4px;">ARCIS-SWARM · Health Report</div>
    <h1 style="font-size:22px;color:#e2e8f0;font-weight:700;">{_esc(cl_name)}</h1>
    <div style="margin-top:6px;font-size:12px;color:#64748b;">{_esc(now_str)}</div>
  </div>
  <div style="text-align:right;font-size:12px;">
    <div style="color:#475569;">Cluster state</div>
    <div style="color:{state_col};font-size:16px;font-weight:700;">{_esc(cl_state.upper())}</div>
    <div style="color:#334155;margin-top:4px;">{len(nodes_parsed)} nodes reporting</div>
  </div>
</div>

<!-- KPIs -->
<div style="display:flex;gap:16px;margin-bottom:28px;flex-wrap:wrap;">
  <div style="background:#16213e;border:1px solid #1a1a4e;border-radius:8px;padding:12px 20px;min-width:110px;">
    <div style="color:#475569;font-size:10px;text-transform:uppercase;letter-spacing:.08em;">Nodes</div>
    <div style="font-size:28px;font-weight:700;color:#7dd3fc;">{len(nodes_parsed)}</div>
  </div>
  <div style="background:#16213e;border:1px solid #1a1a4e;border-radius:8px;padding:12px 20px;min-width:120px;">
    <div style="color:#475569;font-size:10px;text-transform:uppercase;letter-spacing:.08em;">Drives</div>
    <div style="font-size:28px;font-weight:700;color:#a5f3fc;">{total_drives}</div>
  </div>
  <div style="background:#16213e;border:1px solid #1a1a4e;border-radius:8px;padding:12px 20px;min-width:130px;">
    <div style="color:#475569;font-size:10px;text-transform:uppercase;letter-spacing:.08em;">Volumes</div>
    <div style="font-size:28px;font-weight:700;color:#c4b5fd;">{total_vols}</div>
  </div>
  <div style="background:#16213e;border:1px solid #1a1a4e;border-radius:8px;padding:12px 20px;min-width:200px;">
    <div style="color:#475569;font-size:10px;text-transform:uppercase;letter-spacing:.08em;">Cluster Capacity</div>
    <div style="font-size:20px;font-weight:700;color:#f0fdf4;">{nodes_parsed[0]["cl_total_tb"]} TB <span style="font-size:13px;color:#64748b;">licensed · {nodes_parsed[0]["cl_avail_tb"]} TB avail</span></div>
  </div>
</div>

<!-- Node summary table -->
<div style="margin-bottom:32px;">
  <div class="section-title">Node Summary</div>
  <div style="overflow-x:auto;">
    <table style="width:100%;border-collapse:collapse;font-size:12px;">
      <thead>
        <tr style="border-bottom:1px solid #334155;">
          <th style="padding:8px 10px;color:#475569;font-weight:400;text-align:left;">IP</th>
          <th style="padding:8px 10px;color:#475569;font-weight:400;text-align:left;">Version</th>
          <th style="padding:8px 10px;color:#475569;font-weight:400;text-align:center;">Memory</th>
          <th style="padding:8px 10px;color:#475569;font-weight:400;text-align:left;">Volumes (top 3)</th>
          <th style="padding:8px 10px;color:#475569;font-weight:400;text-align:center;">Drives</th>
          <th style="padding:8px 10px;color:#475569;font-weight:400;text-align:left;">HP Cycle</th>
          <th style="padding:8px 10px;color:#475569;font-weight:400;text-align:center;">State</th>
          <th style="padding:8px 10px;color:#475569;font-weight:400;text-align:center;">Ann.</th>
        </tr>
      </thead>
      <tbody>{summary_rows}</tbody>
    </table>
  </div>
</div>

<!-- Node details -->
<div>
  <div class="section-title">Node Details</div>
  {detail_sections}
</div>

</body>
</html>"""


def _no_data_page() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><title>ARCIS-SWARM — Health Report</title>
<style>body{background:#0f0f1e;color:#e2e8f0;font-family:'Courier New',monospace;
  display:flex;align-items:center;justify-content:center;min-height:100vh;}</style>
</head>
<body>
  <div style="text-align:center;">
    <div style="color:#3b82f6;font-size:10px;letter-spacing:.15em;margin-bottom:8px;">ARCIS-SWARM</div>
    <h1 style="color:#475569;font-size:18px;">No health report data available</h1>
    <p style="color:#334155;margin-top:8px;font-size:12px;">
      Run an audit on a gateway node with swarmctl to collect per-node healthreport data.
    </p>
  </div>
</body>
</html>"""
