# Version: 3.1.0
# Date:    2026-06-20
# Notes:   Longer retry waits + inter-call gap for hub_mcp 429 resilience

from __future__ import annotations
import asyncio
import json
import logging
import time
import urllib.request
from typing import Callable, Optional

from models import AuditResult, AnalysisResult, AnalysisModule, AnalysisFinding

log = logging.getLogger(__name__)

CLAUDE_MODEL = "claude-sonnet-4-6"

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
    "LISTING_CACHE", "LISTING_CACHE_SERVER", "SCS", "UNKNOWN",
)}
_DEFAULT_RAG_INDICES = _ALL_RAG_INDICES

MODULE_SCHEMA = """{
  "role": "ROLE_NAME",
  "servers": ["server_name"],
  "summary": "one-line overall assessment",
  "config_findings": [{"severity":"CRITICAL|WARNING|INFO|OK","title":"...","detail":"...","recommendation":"...","servers":["..."]}],
  "log_findings": []
}"""

CROSS_SCHEMA = """{
  "cross_correlations": [{"severity":"CRITICAL|WARNING|INFO|OK","title":"...","detail":"...","recommendation":"...","servers":["...","..."]}]
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
    mcp_url: str, token: str, arguments: dict, max_attempts: int = 6
) -> dict:
    """Call ask_claude with exponential backoff on 429 rate-limit errors."""
    # Delays: 60s, 90s, 120s, 180s, 240s between attempts
    waits = [60, 90, 120, 180, 240]
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
    resp = _ask_claude_with_retry(mcp_url, mcp_token, ask_args)
    if resp.get("result", {}).get("isError"):
        err_content = resp.get("result", {}).get("content", [])
        err_text = err_content[0].get("text", "unknown error") if err_content else "unknown error"
        raise ValueError(f"ask_claude returned error: {err_text}")
    text = _extract_ask_claude_answer(resp)
    if not text:
        raise ValueError("ask_claude returned empty response")
    return text


def _group_by_role(results: list[AuditResult]) -> dict[str, list[AuditResult]]:
    """Group servers by detected role. Multi-role servers appear in each group.
    Failed servers (success=False) land in UNKNOWN."""
    groups: dict[str, list[AuditResult]] = {}
    for r in results:
        if not r.success or not r.roles:
            groups.setdefault("UNKNOWN", []).append(r)
            continue
        for rd in r.roles:
            role = rd.role or "UNKNOWN"
            groups.setdefault(role, []).append(r)
    return groups


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
    """Parse a list of finding dicts into AnalysisFinding objects."""
    out: list[AnalysisFinding] = []
    for f in lst or []:
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

        # Inter-call gap for hub_mcp to reduce burst 429s
        if not want_direct:
            await asyncio.sleep(5)

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
            "You are a senior DataCore Swarm infrastructure architect performing a configuration audit.\n"
            "Analyze ONLY the configuration files provided — do not speculate about logs or runtime state.\n"
            "Return ONLY valid JSON — no text, no markdown, no code fences.\n"
            "Severity: CRITICAL (immediate risk), WARNING (should fix), INFO (observation), OK (correct).\n"
            "Cite actual values from the config files. Minimum 2 findings. Include positive OK findings.\n"
            "log_findings must be an empty array []."
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
            data = json.loads(raw)
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
    data = json.loads(raw)
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
    # Limit concurrency: hub_mcp is rate-limited (1), direct can do 3 in parallel
    concurrency = 1 if want_hub_mcp else 3
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
