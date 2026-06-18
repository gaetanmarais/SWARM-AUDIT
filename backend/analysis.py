# Version: 1.0.0
# Date:    2026-06-18
# Notes:   Post-audit AI analysis: MCP RAG (multiple Swarm skills) + Claude API

from __future__ import annotations
import asyncio
import json
import logging
import urllib.request
from typing import Optional

from models import AuditResult, AnalysisResult, AnalysisModule, AnalysisFinding

log = logging.getLogger(__name__)

MCP_URL = "https://claude-ws-gmarais.duckdns.org/mcp"
CLAUDE_MODEL = "claude-sonnet-4-6"

# Multiple targeted queries to hit the various Swarm skill/RAG collections
# (swarm, swarm-elasticsearch, swarm-gateway, swarm-haproxy-ssl, swarm-storage-nodes, etc.)
RAG_QUERIES = [
    "HAProxy DataCore Swarm load balancer maxconn TCP connection limits backend server configuration",
    "Content Gateway DataCore Swarm HTTP performance tuning connection pool configuration parameters",
    "Elasticsearch DataCore Swarm cluster health JVM heap memory shards index configuration",
    "Castor Swarm storage nodes health replication erasure coding disk volume castor.log errors",
    "Listing Cache Server LCS RabbitMQ Redis DataCore Swarm configuration performance",
    "SCS CSN platform server DataCore Swarm cluster services NTP DHCP syslog configuration",
    "DataCore Swarm common errors troubleshooting log analysis disk failure recovery",
    "DataCore Swarm network NIC bonding multicast VLAN IGMP snooping configuration",
    "DataCore Swarm replication policy erasure coding best practices sizing memory",
    "HAProxy SSL TLS offload DataCore Swarm frontend backend ACL configuration",
]

SYSTEM_PROMPT = """You are a senior DataCore Swarm infrastructure architect performing a configuration and log audit.

Analyze the infrastructure audit data below and return a structured JSON analysis.

Rules:
- Return ONLY valid JSON — no text, no markdown, no code fences
- Severity: CRITICAL (immediate risk), WARNING (should fix), INFO (observation/best practice), OK (positive/correct)
- For each finding: cite actual values from the data (parameter names, thresholds, counts)
- Cross-correlations: identify mismatches that span components (e.g. HAProxy maxconn=2000 but Gateway allows 8000 connections — the bottleneck shifts to HAProxy; ES JVM heap vs total RAM ratio)
- Log analysis: identify error patterns, frequencies, root causes; correlate log errors with config issues
- Cover ALL servers and ALL detected roles — include at least 2 findings per module
- Include positive OK findings when configuration is correct"""

RESPONSE_SCHEMA = """{
  "modules": [
    {
      "role": "ROLE_NAME (e.g. HAPROXY, CONTENT_GATEWAY, ELASTICSEARCH, CASTOR, SCS, LISTING_CACHE_SERVER)",
      "servers": ["server_name"],
      "summary": "one-line overall assessment (positive or negative)",
      "config_findings": [
        {
          "severity": "CRITICAL|WARNING|INFO|OK",
          "title": "concise title",
          "detail": "specific detail with actual parameter names and values from audit data",
          "recommendation": "concrete actionable recommendation",
          "servers": ["server_name"]
        }
      ],
      "log_findings": [
        {
          "severity": "CRITICAL|WARNING|INFO|OK",
          "title": "concise title",
          "detail": "log pattern with message examples and occurrence counts",
          "recommendation": "actionable recommendation or 'None required'",
          "servers": ["server_name"]
        }
      ]
    }
  ],
  "cross_correlations": [
    {
      "severity": "CRITICAL|WARNING|INFO|OK",
      "title": "concise title",
      "detail": "cross-component issue with specific values from both sides",
      "recommendation": "actionable recommendation",
      "servers": ["server_name1", "server_name2"]
    }
  ]
}"""


def _mcp_call_sync(token: str, tool: str, arguments: dict) -> dict:
    """Synchronous MCP tool call via urllib (no extra deps)."""
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }).encode()
    req = urllib.request.Request(
        MCP_URL,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        log.warning("MCP call %s failed: %s", tool, exc)
        return {}


def _extract_rag_text(response: dict) -> str:
    """Extract readable text from a search_workspace_rag MCP response."""
    try:
        content = response.get("result", {}).get("content", [])
        if isinstance(content, list):
            return "\n---\n".join(
                item.get("text", "") for item in content if isinstance(item, dict)
            )
        return str(response.get("result", ""))
    except Exception:
        return ""


def _server_summary(r: AuditResult) -> str:
    """Compact text summary of a server for the Claude prompt."""
    lines: list[str] = [f"=== {r.server_name} ({r.server_ip}) ==="]

    if not r.success:
        lines.append(f"  AUDIT FAILED: {r.error}")
        return "\n".join(lines)

    roles_str = ", ".join(rd.role for rd in r.roles) or "UNKNOWN"
    lines.append(f"  Roles: {roles_str}")
    lines.append(f"  OS: {r.os}  Kernel: {r.kernel}  Uptime: {(r.uptime_sec or 0)//3600}h")

    if r.cpu:
        lines.append(f"  CPU: {r.cpu.count} cores — {r.cpu.model}")
    if r.ram:
        used_pct = round((1 - r.ram.free_mb / r.ram.total_mb) * 100) if r.ram.total_mb else 0
        lines.append(f"  RAM: {r.ram.total_mb} MB total  {r.ram.free_mb} MB free ({used_pct}% used)")

    for d in r.disks[:6]:
        lines.append(f"  Disk {d.mount}: {d.size_gb} GB total  {d.avail_gb} GB free ({d.used_pct} used)")

    if r.network_interfaces:
        ifs = [f"{ni.iface}:{ni.ip}" for ni in r.network_interfaces[:4]]
        lines.append(f"  Interfaces: {', '.join(ifs)}")

    if r.listen_ports:
        lines.append(f"  Listen ports: {', '.join(lp.port for lp in r.listen_ports[:20])}")

    if r.config_contents:
        lines.append("  CONFIG FILES:")
        for path, content in list(r.config_contents.items())[:8]:
            lines.append(f"    [{path}]\n{content[:2500]}")

    if r.haproxy_vips:
        lines.append(f"  HAProxy VIPs: {', '.join(r.haproxy_vips)}")
    if r.haproxy_backends:
        be = [f"{b.name}/{b.ip}:{b.port}" for b in r.haproxy_backends]
        lines.append(f"  HAProxy backends: {', '.join(be)}")

    if r.gw_cluster_ips:
        lines.append(f"  GW→Swarm cluster: {', '.join(r.gw_cluster_ips)}")
    if r.gw_es_ips:
        lines.append(f"  GW→ES: {', '.join(r.gw_es_ips)}")
    if r.gw_lcs_ips:
        lines.append(f"  GW→LCS: {', '.join(r.gw_lcs_ips)}")

    if r.es_cluster_name:
        lines.append(f"  ES cluster: {r.es_cluster_name}")
    if r.es_cat_health:
        lines.append(f"  ES health:\n{r.es_cat_health[:600]}")
    if r.es_cat_nodes:
        lines.append(f"  ES nodes:\n{r.es_cat_nodes[:1000]}")
    if r.es_cat_indices:
        lines.append(f"  ES indices:\n{r.es_cat_indices[:800]}")
    if r.es_cat_alloc:
        lines.append(f"  ES disk alloc:\n{r.es_cat_alloc[:500]}")
    if r.es_node_stats:
        lines.append(f"  ES node stats:\n{r.es_node_stats[:800]}")

    if r.discovered_storage_nodes:
        lines.append(f"  Storage nodes ({len(r.discovered_storage_nodes)} discovered):")
        for sn in r.discovered_storage_nodes[:12]:
            lines.append(
                f"    {sn.ip}: avail={sn.avail_pct} used={sn.used} "
                f"streams={sn.streams} errors={sn.errors} version={sn.version}"
            )
    if r.swarm_cluster_summary:
        lines.append(f"  Swarm cluster summary:\n{r.swarm_cluster_summary[:800]}")

    svcs = [s for s, v in [
        ("syslog", r.is_syslog_server), ("NTP", r.is_ntp_server),
        ("DHCP", r.is_dhcp_server), ("PXE", r.is_pxe_server),
    ] if v]
    if svcs:
        lines.append(f"  Infrastructure services: {', '.join(svcs)}")

    if r.installed_packages:
        pkgs = [f"{p.name}-{p.version}" for p in r.installed_packages[:20]]
        lines.append(f"  Key packages: {', '.join(pkgs)}")

    if r.logs:
        lines.append("  LOGS last 24h (deduplicated):")
        for role_key, log_content in r.logs.items():
            if log_content:
                lines.append(f"    [{role_key}]\n{log_content[:3500]}")

    return "\n".join(lines)


async def run_analysis(
    results: list[AuditResult],
    mcp_token: str,
    anthropic_key: str,
    cancel_flag: list[bool],
) -> AnalysisResult:
    """
    Run AI analysis on audit results.
    cancel_flag[0] = True → abort with CancelledError.
    """
    import anthropic as _anthropic  # lazy import — not in default deps

    loop = asyncio.get_event_loop()

    # ── 1. RAG context from Hub MCP (multiple Swarm skills) ─────────────────
    rag_parts: list[str] = []
    if mcp_token:
        log.info("Fetching Swarm RAG context (%d queries)…", len(RAG_QUERIES))
        seen: set[str] = set()
        for query in RAG_QUERIES:
            if cancel_flag[0]:
                raise asyncio.CancelledError()
            resp = await loop.run_in_executor(
                None, _mcp_call_sync, mcp_token, "search_workspace_rag",
                {"query": query, "k": 5},
            )
            text = _extract_rag_text(resp).strip()
            # Deduplicate near-identical results
            key = text[:200]
            if text and key not in seen:
                seen.add(key)
                rag_parts.append(f"[{query}]\n{text}")
        log.info("RAG: %d unique results, ~%d chars", len(rag_parts),
                 sum(len(p) for p in rag_parts))

    if cancel_flag[0]:
        raise asyncio.CancelledError()

    # ── 2. Build prompt ──────────────────────────────────────────────────────
    servers_text = "\n\n".join(_server_summary(r) for r in results)

    prompt = "INFRASTRUCTURE AUDIT DATA:\n" + servers_text

    if rag_parts:
        # Cap RAG at 14 000 chars to keep total prompt manageable
        rag_text = "\n\n".join(rag_parts)[:14000]
        prompt += (
            "\n\nSWARM KNOWLEDGE BASE (best practices / known issues "
            "— from multiple Swarm skills and RAG collections):\n" + rag_text
        )

    prompt += f"""

TASK: Analyze the complete infrastructure above.
Return ONLY a JSON object matching this schema exactly:
{RESPONSE_SCHEMA}

Important:
- Cover ALL servers and ALL detected roles
- Cite exact parameter names and values from the audit data
- Correlate across components (HAProxy ↔ Gateway limits, ES heap ↔ RAM, GW TCP pool ↔ Castor nodes count, etc.)
- For log analysis: cite message excerpts, mention occurrence counts [xN] when available
- At least 2 findings per module; positive OK findings are valuable
"""

    # ── 3. Call Claude API ───────────────────────────────────────────────────
    log.info("Calling Claude API (model=%s, ~%d chars)…", CLAUDE_MODEL, len(prompt))

    client = _anthropic.AsyncAnthropic(api_key=anthropic_key)

    if cancel_flag[0]:
        raise asyncio.CancelledError()

    response = await client.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    raw_text: str = response.content[0].text if response.content else "{}"

    # Strip markdown code fences if Claude adds them despite instructions
    for fence_open in ("```json\n", "```json", "```\n", "```"):
        if fence_open in raw_text:
            raw_text = raw_text.split(fence_open, 1)[1]
            raw_text = raw_text.split("```", 1)[0]
            break

    # ── 4. Parse and build AnalysisResult ────────────────────────────────────
    try:
        data = json.loads(raw_text.strip())
    except json.JSONDecodeError as exc:
        log.error("Claude returned invalid JSON: %s | excerpt: %s", exc, raw_text[:300])
        raise ValueError(f"Claude returned invalid JSON: {exc}") from exc

    def _findings(raw_list: list) -> list[AnalysisFinding]:
        out = []
        for f in raw_list or []:
            try:
                out.append(AnalysisFinding(
                    severity=f.get("severity", "INFO"),
                    title=f.get("title", ""),
                    detail=f.get("detail", ""),
                    recommendation=f.get("recommendation", ""),
                    servers=f.get("servers", []),
                ))
            except Exception:
                pass
        return out

    modules = [
        AnalysisModule(
            role=m.get("role", "UNKNOWN"),
            servers=m.get("servers", []),
            summary=m.get("summary", ""),
            config_findings=_findings(m.get("config_findings", [])),
            log_findings=_findings(m.get("log_findings", [])),
        )
        for m in data.get("modules", [])
    ]

    return AnalysisResult(
        status="done",
        modules=modules,
        cross_correlations=_findings(data.get("cross_correlations", [])),
    )
