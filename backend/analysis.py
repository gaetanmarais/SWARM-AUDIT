# Version: 3.5.2
# Date:    2026-06-20
# Notes:   Fix JSON truncation — cap max_tokens at 8000, add conciseness constraint

from __future__ import annotations
import asyncio
import json
import logging
import time
import urllib.request
from typing import Callable, Optional

from models import AuditResult, AnalysisResult, AnalysisModule, AnalysisFinding

log = logging.getLogger(__name__)

CLAUDE_MODEL = "claude-haiku-4-5-20251001"

# One query per Swarm RAG skill available in the Hub
RAG_QUERIES = [
    "HAProxy DataCore Swarm load balancer maxconn TCP connection limits backend server configuration",          # 0  swarm-haproxy-ssl
    "HAProxy SSL TLS offload DataCore Swarm frontend backend ACL certificate configuration",                   # 1  swarm-haproxy-ssl
    "Content Gateway DataCore Swarm HTTP S3 performance tuning connection pool configuration parameters",       # 2  swarm-gateway
    "DataCore Swarm gateway S3 access policy bucket authentication CORS configuration",                        # 3  swarm-gateway
    "Elasticsearch DataCore Swarm cluster health JVM heap memory shards index configuration",                  # 4  swarm-elasticsearch
    "Elasticsearch DataCore Swarm index lifecycle ILM shard allocation replica configuration",                 # 5  swarm-elasticsearch
    "Castor DataCore Swarm storage nodes health replication erasure coding disk volume errors",                 # 6  swarm-storage-nodes
    "DataCore Swarm storage node sizing capacity planning disk failure replacement procedure",                  # 7  swarm-storage-nodes
    "DataCore Swarm replication policy erasure coding best practices sizing memory protection",                 # 8  swarm-replication
    "DataCore Swarm replication domain protection level cross-cluster configuration",                          # 9  swarm-replication
    "Listing Cache Server LCS RabbitMQ Redis DataCore Swarm configuration performance tuning",                 # 10 swarm (LCS)
    "SCS CSN platform server DataCore Swarm cluster services NTP DHCP syslog configuration",                  # 11 swarm (SCS)
    "DataCore Swarm architecture cluster deployment network multicast VLAN IGMP configuration",                # 12 swarm (core)
    "DataCore Swarm how-to troubleshooting best practices installation upgrade procedure",                     # 13 swarm-howto
    "DataCore Swarm common errors disk failure recovery cluster rebuild procedure",                            # 14 swarm-howto
    "FileFly DataCore file migration policy tiering lifecycle content gateway configuration",                  # 15 swarm-filefly
    "DataCore Swarm monitoring SNMP alerting metrics healthreport cluster status performance",                 # 16 swarm-monitoring
    "DataCore Swarm monitoring dashboard alerts threshold configuration Prometheus Grafana",                   # 17 swarm-monitoring
]

# All RAG indices — sent to every role so no skill is missed
_ALL_RAG_INDICES = list(range(len(RAG_QUERIES)))

ROLE_RAG_MAP: dict[str, list[int]] = {role: _ALL_RAG_INDICES for role in (
    "HAPROXY", "CONTENT_GATEWAY", "ELASTICSEARCH", "CASTOR", "STORAGE_NODE",
    "LISTING_CACHE", "LISTING_CACHE_SERVER", "SCS", "TELEMETRY", "UNKNOWN",
)}
_DEFAULT_RAG_INDICES = _ALL_RAG_INDICES

MODULE_SCHEMA = """{
  "role": "ROLE_NAME",
  "servers": ["server_name"],
  "summary": "one-line overall assessment",
  "config_findings": [
    {
      "severity": "CRITICAL|WARNING|INFO|OK",
      "title": "Short title",
      "detail": "Explain what is wrong and why it matters",
      "current_value": "Exact line(s) from the config file that are misconfigured, e.g. 'xpack.security.enabled: false'",
      "corrected_config": "Ready-to-paste corrected config snippet with the exact parameter names and values",
      "recommendation": "Actionable step to fix, referencing DataCore Swarm best practices when applicable",
      "doc_reference": "DataCore documentation title or section that covers this setting, if found in the knowledge base",
      "servers": ["server_name"]
    }
  ],
  "log_findings": [
    {
      "severity": "CRITICAL|WARNING|INFO|OK",
      "title": "Short title describing the log pattern",
      "detail": "Explain what the log pattern indicates and why it matters",
      "current_value": "Representative log line(s) — e.g. '[x47] ERROR: Connection refused to 10.x.x.x:9200'",
      "corrected_config": "Configuration fix that would resolve this log pattern, if applicable",
      "recommendation": "What to investigate or fix based on these log patterns",
      "doc_reference": "DataCore doc reference if relevant",
      "servers": ["server_name"]
    }
  ]
}"""

CROSS_SCHEMA = """{
  "cross_correlations": [
    {
      "severity": "CRITICAL|WARNING|INFO|OK",
      "title": "Short title",
      "detail": "Explain the cross-component mismatch and its impact",
      "current_value": "The conflicting values from each side, e.g. 'HAProxy maxconn=10000 vs GW threads=200'",
      "corrected_config": "Corrected values for each affected component",
      "recommendation": "How to align the components",
      "doc_reference": "DataCore documentation title or section that covers this setting, if found in the knowledge base",
      "servers": ["server_a", "server_b"]
    }
  ]
}"""


def _call_anthropic_direct(api_key: str, prompt: str, system: str) -> str:
    """Call api.anthropic.com/v1/messages directly — bypass Hub MCP ask_claude."""
    payload = json.dumps({
        "model": CLAUDE_MODEL,
        "max_tokens": 8000,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read())
            for block in data.get("content", []):
                if block.get("type") == "text":
                    return block["text"]
        return ""
    except Exception as exc:
        log.error("Direct Anthropic API call failed: %s", exc)
        raise ValueError(f"Direct Anthropic API call failed: {exc}")


def _mcp_call_sync(mcp_url: str, token: str, tool: str, arguments: dict) -> dict:
    """Synchronous MCP tool call via urllib (no extra deps)."""
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }).encode()
    req = urllib.request.Request(
        mcp_url,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        log.warning("MCP call %s failed: %s", tool, exc)
        return {}


def _ask_claude_with_retry(
    mcp_url: str, token: str, arguments: dict, max_attempts: int = 3
) -> dict:
    """Call ask_claude with exponential backoff on 429 rate-limit errors.
    Fail fast: 3 attempts max, waits [30s, 60s] — total <2min before giving up.
    """
    waits = [30, 60, 90]
    for attempt in range(max_attempts):
        resp = _mcp_call_sync(mcp_url, token, "ask_claude", arguments)
        if not resp:
            if attempt < max_attempts - 1:
                wait = waits[min(attempt, len(waits) - 1)]
                log.warning("ask_claude empty response (attempt %d/%d), retrying in %ds…",
                            attempt + 1, max_attempts, wait)
                time.sleep(wait)
                continue
            return resp

        # Check for 429 in the MCP error content
        content = resp.get("result", {}).get("content", [])
        err_text = ""
        if isinstance(content, list) and content:
            err_text = content[0].get("text", "")
        is_rate_limit = (
            "429" in err_text
            or "rate_limit_error" in err_text
            or resp.get("result", {}).get("isError") and "429" in str(resp)
        )
        if is_rate_limit and attempt < max_attempts - 1:
            wait = waits[min(attempt, len(waits) - 1)]
            log.warning("ask_claude hit 429 rate limit (attempt %d/%d), waiting %ds…",
                        attempt + 1, max_attempts, wait)
            time.sleep(wait)
            continue

        return resp
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


def _extract_ask_claude_answer(response: dict) -> str:
    """Extract the answer text from an ask_claude MCP response."""
    try:
        content = response.get("result", {}).get("content", [])
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    text = item.get("text", "")
                    # ask_claude returns a JSON-encoded dict with "answer" key
                    try:
                        parsed = json.loads(text)
                        if isinstance(parsed, dict) and "answer" in parsed:
                            return parsed["answer"]
                    except Exception:
                        pass
                    return text
        return ""
    except Exception:
        return ""


def _server_summary(r: AuditResult) -> str:
    """Compact config-only summary for the Claude prompt (keeps token count low)."""
    lines: list[str] = [f"=== {r.server_name} ({r.server_ip}) ==="]

    if not r.success:
        lines.append(f"  AUDIT FAILED: {r.error}")
        return "\n".join(lines)

    roles_str = ", ".join(rd.role for rd in r.roles) or "UNKNOWN"
    lines.append(f"  Roles: {roles_str}")
    lines.append(f"  OS: {r.os}  Kernel: {r.kernel}")

    if r.listen_ports:
        lines.append(f"  Listen ports: {', '.join(lp.port for lp in r.listen_ports[:20])}")

    if r.config_contents:
        lines.append("  CONFIG FILES:")
        for path, content in list(r.config_contents.items())[:8]:
            lines.append(f"    [{path}]\n{content[:2000]}")

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

    if r.swarm_cluster_summary:
        lines.append(f"  SWARM CLUSTER SUMMARY:\n{r.swarm_cluster_summary[:3000]}")

    if r.discovered_storage_nodes:
        lines.append(f"  STORAGE NODES ({len(r.discovered_storage_nodes)} discovered):")
        for node in r.discovered_storage_nodes[:30]:
            lines.append(
                f"    {node.ip}: status={node.status} avail={node.avail_pct}%"
                f" used={node.used}/{node.max} streams={node.streams}"
                f" errors={node.errors or 'none'}"
            )

    if r.logs:
        lines.append("  APPLICATION LOGS (last 24h, deduplicated — format [xN] = N occurrences):")
        for role_key, log_text in r.logs.items():
            if log_text:
                snippet = log_text[:3000]
                if len(log_text) > 3000:
                    snippet += f"\n  ... ({len(log_text) - 3000} more chars truncated)"
                lines.append(f"    [{role_key} logs]\n{snippet}")

    return "\n".join(lines)


# ── New helpers ──────────────────────────────────────────────────────────────

def _strip_fences(text: str) -> str:
    """Strip ```json … ``` fences from a Claude response."""
    for fence_open in ("```json\n", "```json", "```\n", "```"):
        if fence_open in text:
            text = text.split(fence_open, 1)[1]
            text = text.split("```", 1)[0]
            break
    return text.strip()


def _parse_json_robust(raw: str) -> dict:
    """Parse JSON, with a fallback that recovers from a truncated response.

    If the raw string is cut mid-string (common when max_tokens is hit), try
    to find the longest complete top-level object by scanning backwards for a
    balanced closing brace.
    """
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        log.warning("JSON parse failed at char %d, attempting recovery…", exc.pos)

    # Walk backwards to find the last position where brace depth returns to 0
    depth = 0
    last_valid_end = -1
    in_string = False
    escape = False
    for i, ch in enumerate(raw):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                last_valid_end = i

    if last_valid_end > 0:
        try:
            return json.loads(raw[:last_valid_end + 1])
        except json.JSONDecodeError:
            pass

    raise json.JSONDecodeError("Cannot recover truncated JSON", raw, len(raw))


def _call_claude_sync(
    prompt: str,
    system: str,
    want_direct: bool,
    api_key: str,
    mcp_url: str,
    mcp_token: str,
) -> str:
    """Unified sync Claude caller — direct Anthropic API or Hub MCP ask_claude."""
    if want_direct:
        return _call_anthropic_direct(api_key, prompt, system)

    # hub_mcp: ask_claude has no system param — embed system at top of prompt
    full_prompt = f"{system}\n\n{prompt}"
    ask_args: dict = {"prompt": full_prompt, "model": CLAUDE_MODEL}
    # Pass api_key to ask_claude so it uses a dedicated Anthropic account
    # instead of the Hub's shared OAuth token (avoids shared-quota 429s)
    if api_key:
        ask_args["api_key"] = api_key
    resp = _ask_claude_with_retry(mcp_url, mcp_token, ask_args)
    if resp.get("result", {}).get("isError"):
        err_content = resp.get("result", {}).get("content", [])
        err_text = err_content[0].get("text", "unknown error") if err_content else "unknown error"
        raise ValueError(f"ask_claude returned error: {err_text}")
    text = _extract_ask_claude_answer(resp)
    if not text:
        raise ValueError("ask_claude returned empty response")
    return text


# Canonical display order — mirrors the SVG diagram layers
ROLE_ORDER = [
    "HAPROXY",
    "SCS", "CSN_PLATFORM",
    "CONTENT_GATEWAY",
    "LISTING_CACHE_SERVER", "LISTING_CACHE",
    "ELASTICSEARCH",
    "CASTOR", "STORAGE_NODE",
    "TELEMETRY",
    "FOUNDATION_DB", "SWARMFS", "CONTENT_UI", "STORAGE_UI",
    "UNKNOWN",
]

SEVERITY_ORDER = {"CRITICAL": 0, "WARNING": 1, "INFO": 2, "OK": 3}


def _group_by_role(results: list[AuditResult]) -> dict[str, list[AuditResult]]:
    """Group servers by detected role, ordered per ROLE_ORDER.
    Multi-role servers appear in each group.
    Failed servers (success=False) land in UNKNOWN."""
    groups: dict[str, list[AuditResult]] = {}
    for r in results:
        if not r.success or not r.roles:
            groups.setdefault("UNKNOWN", []).append(r)
            continue
        for rd in r.roles:
            role = rd.role or "UNKNOWN"
            groups.setdefault(role, []).append(r)
    # Re-order according to ROLE_ORDER, unknown roles appended at the end
    ordered: dict[str, list[AuditResult]] = {}
    for role in ROLE_ORDER:
        if role in groups:
            ordered[role] = groups.pop(role)
    ordered.update(groups)  # any leftover roles not in ROLE_ORDER
    return ordered


async def _fetch_rag_cache(
    needed_indices: set[int],
    mcp_url: str,
    mcp_token: str,
    loop: asyncio.AbstractEventLoop,
    cancel_flag: list[bool],
) -> dict[int, str]:
    """Fetch deduplicated RAG queries upfront; returns {index: text}.
    Returns empty dict if no token is available."""
    if not mcp_token or not mcp_url:
        return {}

    cache: dict[int, str] = {}
    seen_keys: set[str] = set()

    for idx in sorted(needed_indices):
        if cancel_flag[0]:
            raise asyncio.CancelledError()
        query = RAG_QUERIES[idx]
        resp = await loop.run_in_executor(
            None, _mcp_call_sync, mcp_url, mcp_token,
            "search_workspace_rag", {"query": query, "k": 5},
        )
        text = _extract_rag_text(resp).strip()
        key = text[:200]
        if text and key not in seen_keys:
            seen_keys.add(key)
            cache[idx] = text
        log.debug("RAG idx=%d: %d chars", idx, len(text))

    log.info("RAG cache: %d/%d indices populated", len(cache), len(needed_indices))
    return cache


def _parse_findings(lst: list) -> list[AnalysisFinding]:
    """Parse finding dicts into AnalysisFinding objects, sorted CRITICAL→WARNING→INFO→OK."""
    out: list[AnalysisFinding] = []
    for f in lst or []:
        try:
            out.append(AnalysisFinding(
                severity=f.get("severity", "INFO"),
                title=f.get("title", ""),
                detail=f.get("detail", ""),
                current_value=f.get("current_value", ""),
                corrected_config=f.get("corrected_config", ""),
                recommendation=f.get("recommendation", ""),
                doc_reference=f.get("doc_reference", ""),
                servers=f.get("servers", []),
            ))
        except Exception:
            pass
    out.sort(key=lambda x: SEVERITY_ORDER.get(x.severity, 99))
    return out


async def _analyze_role_group(
    role: str,
    servers: list[AuditResult],
    rag_cache: dict[int, str],
    sem: asyncio.Semaphore,
    want_direct: bool,
    api_key: str,
    mcp_url: str,
    mcp_token: str,
    cancel_flag: list[bool],
    loop: asyncio.AbstractEventLoop,
) -> AnalysisModule:
    """Analyze one role group with a single Claude call. Returns AnalysisModule."""
    async with sem:
        if cancel_flag[0]:
            raise asyncio.CancelledError()

        # Build server summaries block
        server_summaries = "\n\n".join(_server_summary(r) for r in servers)

        # Build RAG block for this role
        indices = ROLE_RAG_MAP.get(role, _DEFAULT_RAG_INDICES)
        rag_parts = [rag_cache[i] for i in indices if i in rag_cache]
        rag_block = ""
        if rag_parts:
            rag_text = "\n\n".join(rag_parts)[:16000]
            rag_block = f"\nSWARM KNOWLEDGE BASE:\n{rag_text}"

        system = (
            "You are a senior DataCore Swarm infrastructure architect performing a configuration and log audit.\n"
            "Analyze the configuration files AND application logs provided below. Do not speculate about information absent from the provided data.\n"
            "Return ONLY valid JSON — no text, no markdown, no code fences.\n"
            "CRITICAL: Your entire response MUST be a single complete valid JSON object. "
            "Limit config_findings to 5 entries max. Limit log_findings to 3 entries max. "
            "Keep 'detail' under 60 words. Keep 'corrected_config' under 6 lines. "
            "Keep 'current_value' under 3 lines. Never truncate the JSON — if content would exceed limits, summarize instead.\n"
            "Severity: CRITICAL (immediate risk), WARNING (should fix), INFO (observation), OK (correct).\n"
            "For every non-OK finding you MUST populate:\n"
            "  current_value: quote the exact line(s) from the config file that are wrong.\n"
            "  corrected_config: provide the exact replacement snippet ready to paste into the config file.\n"
            "  doc_reference: if the SWARM KNOWLEDGE BASE contains a section covering this setting, cite the DataCore\n"
            "    documentation page title and its likely URL on https://documentation.datacore.com/. Only cite if the\n"
            "    knowledge base actually contains relevant content — do not invent URLs.\n"
            "TELEMETRY ROLE (Prometheus / Grafana / Alertmanager): When analyzing a TELEMETRY role, you MUST:\n"
            "  1. WHAT IS MONITORED: List every scrape job (job_name + targets) from prometheus.yml.\n"
            "     For each Swarm component (HAProxy, Gateway, ES, LCS, SCS, Storage nodes, RabbitMQ),\n"
            "     state explicitly whether it is scraped or NOT scraped — missing coverage is a WARNING or CRITICAL.\n"
            "  2. ALERT RULES: For every alert rule file found, list each rule with its expr, 'for' duration,\n"
            "     and threshold values. Flag missing essential Swarm alerts (disk full, ES red, node down,\n"
            "     replication lag, LCS broker failure, HAProxy backend down).\n"
            "  3. ALERT ROUTING: Analyze alertmanager.yml — identify all receivers (email, PagerDuty, Slack,\n"
            "     webhook, etc.), routing tree, group_wait/group_interval/repeat_interval, and inhibit rules.\n"
            "     State explicitly HOW alerts reach the on-call team and whether critical alerts have a dedicated route.\n"
            "  4. GAPS: Explicitly call out components that have NO alert rule coverage — even if they are scraped.\n"
            "VEEAM USE-CASE: This cluster is used as a Veeam Backup & Replication S3 object storage target.\n"
            "  For every role, explicitly check and report (even if OK) the Veeam-relevant settings:\n"
            "  - HAProxy: session timeouts (must be >= 3600s for large Veeam jobs), maxconn sizing for concurrent backup jobs.\n"
            "  - Content Gateway: S3 multipart upload limits, object size limits, connection pool for Veeam agents,\n"
            "      immutability/object locking (required for Veeam Hardened Repository / SOBR immutable tier),\n"
            "      allowSwarmAdminIP restriction (security requirement before prod use with Veeam).\n"
            "  - Elasticsearch: index retention policy compatibility with Veeam metadata indexing if used.\n"
            "  - LCS: RabbitMQ broker redundancy (single broker = risk during Veeam GFS restore operations).\n"
            "  - Storage Nodes: replication factor vs. Veeam backup copy job RPO requirements.\n"
            "LOG ANALYSIS: If APPLICATION LOGS are provided, analyze them and populate log_findings:\n"
            "  - Report recurring errors or warnings (format [xN] means N occurrences — high counts = systemic issue).\n"
            "  - Flag log patterns indicating performance issues, connection failures, or service instability.\n"
            "  - Ignore purely informational/routine lines. Focus on errors, warnings, retries, timeouts.\n"
            "  - If no logs provided or logs are clean, log_findings may be an empty array.\n"
            "Minimum 3 findings per role. Include ALL checked config items as findings (OK or not)."
        )

        prompt = (
            f"ROLE TO ANALYZE: {role}\n\n"
            f"SERVERS:\n{server_summaries}"
            f"{rag_block}\n\n"
            f"Analyze configuration files only. Return ONLY a JSON object for role {role}:\n{MODULE_SCHEMA}"
        )

        log.info("Analyzing role group: %s (%d servers, ~%d chars)…",
                 role, len(servers), len(prompt))

        try:
            raw = await loop.run_in_executor(
                None, _call_claude_sync,
                prompt, system, want_direct, api_key, mcp_url, mcp_token,
            )
            raw = _strip_fences(raw)
            data = _parse_json_robust(raw)
            return AnalysisModule(
                role=data.get("role", role),
                servers=data.get("servers", [s.server_name for s in servers]),
                summary=data.get("summary", ""),
                config_findings=_parse_findings(data.get("config_findings", [])),
                log_findings=_parse_findings(data.get("log_findings", [])),
            )
        except Exception as exc:
            log.error("Role group %s analysis failed: %s", role, exc)
            return AnalysisModule(
                role=role,
                servers=[s.server_name for s in servers],
                summary=f"Analysis failed: {exc}",
                config_findings=[],
                log_findings=[],
            )


def _findings_block(module: AnalysisModule) -> str:
    """Render all findings from a module as compact text for the coherence prompt."""
    lines = [f"=== ROLE: {module.role} | Servers: {', '.join(module.servers)} ===",
             f"  Summary: {module.summary}"]
    for f in module.config_findings + module.log_findings:
        lines.append(
            f"  [{f.severity}] {f.title}\n"
            f"    Detail: {f.detail}\n"
            f"    Recommendation: {f.recommendation}\n"
            f"    Affected: {', '.join(f.servers)}"
        )
    return "\n".join(lines)


async def _run_synthesis(
    modules: list[AnalysisModule],
    results: list[AuditResult],
    want_direct: bool,
    api_key: str,
    mcp_url: str,
    mcp_token: str,
    cancel_flag: list[bool],
    loop: asyncio.AbstractEventLoop,
) -> list[AnalysisFinding]:
    """Phase 2: coherence pass — all findings from all roles, look for cross-component issues."""
    if cancel_flag[0]:
        raise asyncio.CancelledError()

    # Full findings from every role module
    findings_block = "\n\n".join(_findings_block(m) for m in modules)

    # Topology: connectivity between servers
    topo_lines: list[str] = []
    for r in results:
        hb = len(r.haproxy_backends) if r.haproxy_backends else 0
        gc = ", ".join(r.gw_cluster_ips) if r.gw_cluster_ips else "—"
        ge = ", ".join(r.gw_es_ips) if r.gw_es_ips else "—"
        gl = ", ".join(r.gw_lcs_ips) if r.gw_lcs_ips else "—"
        cn = len(r.discovered_storage_nodes) if r.discovered_storage_nodes else 0
        ram = r.ram.total_mb if r.ram else 0
        topo_lines.append(
            f"  {r.server_name} ({r.server_ip}) "
            f"haproxy_backends={hb} gw→swarm={gc} gw→es={ge} "
            f"gw→lcs={gl} castor_nodes={cn} ram={ram}MB"
        )
    topo_block = "\n".join(topo_lines)

    # Key config values extracted per server for cross-referencing
    cfg_lines: list[str] = []
    for r in results:
        if r.config_contents:
            for path, content in list(r.config_contents.items())[:4]:
                cfg_lines.append(f"  [{r.server_name}] {path}:\n{content[:800]}")
    cfg_block = "\n".join(cfg_lines)

    system = (
        "You are a senior DataCore Swarm infrastructure architect performing a cross-component coherence audit.\n"
        "You have received independent per-role analyses. Your job is to find issues that SPAN multiple roles:\n"
        "  - Numerical mismatches (e.g. HAProxy maxconn 10000 but GW connection pool 200 — bottleneck)\n"
        "  - Config values on one side that contradict or are inconsistent with another side\n"
        "  - Missing symmetry (a parameter set on role A that should mirror a setting on role B)\n"
        "  - Version skews, protocol mismatches, or topology gaps\n"
        "  - Recommendations from different roles that conflict with each other\n"
        "Do NOT repeat findings already covered in the per-role analyses. Only surface genuinely cross-cutting issues.\n"
        "For every finding you MUST populate:\n"
        "  current_value: the conflicting values from each component (server name + parameter = value).\n"
        "  corrected_config: the aligned values to set on each affected component.\n"
        "  doc_reference: DataCore documentation page title + URL on https://documentation.datacore.com/ if relevant.\n"
        "    Only cite URLs you are confident exist — do not invent them.\n"
        "Return ONLY valid JSON — no text, no markdown, no code fences.\n"
        "Severity: CRITICAL (immediate risk), WARNING (should fix), INFO (observation)."
    )

    prompt = (
        f"PER-ROLE FINDINGS:\n{findings_block[:10000]}\n\n"
        f"TOPOLOGY & CONNECTIVITY:\n{topo_block}\n\n"
        f"KEY CONFIG EXCERPTS (cross-reference):\n{cfg_block[:4000]}\n\n"
        "Identify coherence issues that span multiple roles or servers.\n"
        f"Return ONLY:\n{CROSS_SCHEMA}"
    )

    log.info("Running coherence synthesis call (~%d chars)…", len(prompt))
    raw = await loop.run_in_executor(
        None, _call_claude_sync,
        prompt, system, want_direct, api_key, mcp_url, mcp_token,
    )
    raw = _strip_fences(raw)
    data = _parse_json_robust(raw)
    return _parse_findings(data.get("cross_correlations", []))


# ── Orchestrator ─────────────────────────────────────────────────────────────

async def run_analysis(
    results: list[AuditResult],
    mcp_url: str,
    mcp_token: str,
    cancel_flag: list[bool],
    anthropic_api_key: str = "",
    analysis_backend: str = "auto",
    on_module_done: Optional[Callable[[AnalysisModule], None]] = None,
    on_progress: Optional[Callable[[str], None]] = None,
) -> AnalysisResult:
    """
    Orchestrate chunked analysis:
      Phase 1 — one Claude call per role group, run in parallel
      Phase 2 — synthesis call for cross-correlations

    analysis_backend: "auto" → prefer direct if api_key set; "hub_mcp" → Hub MCP ask_claude;
                      "direct" → Anthropic API directly.
    cancel_flag[0] = True → abort with CancelledError.
    on_module_done(module) called after each phase-1 module completes.
    on_progress(msg) called with human-readable status strings.
    """
    # Resolve which path to use
    want_direct  = analysis_backend == "direct" or (analysis_backend == "auto" and bool(anthropic_api_key))
    want_hub_mcp = analysis_backend == "hub_mcp" or (analysis_backend == "auto" and not want_direct)

    if want_direct and not anthropic_api_key:
        raise ValueError(
            "Direct API mode selected but no Anthropic API key configured "
            "(set it in Settings or ANTHROPIC_API_KEY env)"
        )
    if want_hub_mcp and not mcp_token:
        raise ValueError(
            "Hub MCP mode selected but no MCP token configured "
            "(set Hub MCP Token in Settings, scope: chat:write + rag:read)"
        )
    if want_hub_mcp and not mcp_url:
        raise ValueError("Hub MCP mode selected but no MCP URL configured")

    loop = asyncio.get_event_loop()

    # ── 1. Group servers by role ─────────────────────────────────────────────
    role_groups = _group_by_role(results)
    n_groups = len(role_groups)
    log.info("Phase 1: %d role groups identified: %s", n_groups, list(role_groups.keys()))

    # ── 2. Fetch RAG upfront (deduplicated) ──────────────────────────────────
    needed: set[int] = set()
    for role in role_groups:
        needed.update(ROLE_RAG_MAP.get(role, _DEFAULT_RAG_INDICES))

    if on_progress:
        on_progress(f"Fetching RAG context ({len(needed)} queries)…")

    rag_cache = await _fetch_rag_cache(needed, mcp_url, mcp_token, loop, cancel_flag)

    if cancel_flag[0]:
        raise asyncio.CancelledError()

    # ── 3. Phase 1: parallel role analysis ──────────────────────────────────
    # hub_mcp: 5 parallel MCP connections (haiku has no per-minute issue at this scale)
    # direct: 5 parallel Anthropic API calls
    concurrency = 5
    sem = asyncio.Semaphore(concurrency)

    if on_progress:
        on_progress(f"Phase 1/2 — {n_groups} role groups…")

    done_count = 0

    async def _analyze_with_cb(role: str, servers: list[AuditResult]) -> AnalysisModule:
        nonlocal done_count
        module = await _analyze_role_group(
            role, servers, rag_cache, sem,
            want_direct, anthropic_api_key, mcp_url, mcp_token,
            cancel_flag, loop,
        )
        done_count += 1
        if on_progress:
            on_progress(f"Phase 1/2 — {done_count}/{n_groups} roles done…")
        if on_module_done:
            on_module_done(module)
        return module

    tasks = [
        _analyze_with_cb(role, servers)
        for role, servers in role_groups.items()
    ]
    modules_raw = await asyncio.gather(*tasks, return_exceptions=True)
    modules = [m for m in modules_raw if isinstance(m, AnalysisModule)]

    if cancel_flag[0]:
        raise asyncio.CancelledError()

    # ── 4. Phase 2: cross-role coherence pass ───────────────────────────────
    if on_progress:
        on_progress("Phase 2/2 — coherence check across all roles…")

    cross_corrs: list[AnalysisFinding] = []
    if modules:
        try:
            cross_corrs = await _run_synthesis(
                modules, results,
                want_direct, anthropic_api_key, mcp_url, mcp_token,
                cancel_flag, loop,
            )
        except Exception as exc:
            log.error("Synthesis failed: %s", exc)

    if on_progress:
        on_progress("")

    return AnalysisResult(status="done", modules=modules, cross_correlations=cross_corrs)
