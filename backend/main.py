# Version: 1.13.0
# Date:    2026-06-20
# Notes:   APP_VERSION watermark in SVG; /api/discover/results adds signals; collected_at in diagram

from __future__ import annotations
import asyncio
import json
import logging
import os
import re
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Response, BackgroundTasks
from pydantic import BaseModel as PydanticBaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from models import (
    Credential, CredentialCreate,
    Server, ServerCreate,
    Inventory, AuditRun, AuditResult,
    AnalysisResult, AnalysisModule, InventorySettings,
)
from audit import run_audit, run_audit_with_discovery, extract_candidate_ips
from svg_gen import generate_svg
from health_report import generate_health_report_html
from analysis import run_analysis
from report_gen import generate_report_html

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

_APP_ROOT        = Path(__file__).parent.parent
DATA_DIR         = Path(os.environ.get("SWARM_DATA_DIR", _APP_ROOT / "data"))
INVENTORY_FILE   = DATA_DIR / "inventory.json"    # servers, audit, analysis, settings
CREDENTIALS_FILE = DATA_DIR / "credentials.json"  # credentials (secrets — never exported)
FRONTEND_DIR     = _APP_ROOT / "frontend"
DUMPS_DIR        = DATA_DIR / "dumps"

APP_VERSION = "2.0.0"
app = FastAPI(title="ARCIS-SWARM", version=APP_VERSION)

# Cache for Tailwind CDN script — fetched once per process lifetime
_tailwind_cdn_cache: str | None = None


def _fetch_tailwind_inline() -> str:
    """Download Tailwind CDN JS and return it as a string. Cached in memory."""
    global _tailwind_cdn_cache
    if _tailwind_cdn_cache is not None:
        return _tailwind_cdn_cache
    try:
        req = urllib.request.Request(
            "https://cdn.tailwindcss.com",
            headers={"User-Agent": "ARCIS-SWARM/1.9 export"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            _tailwind_cdn_cache = resp.read().decode("utf-8")
            log.info("Tailwind CDN fetched and cached (%d bytes)", len(_tailwind_cdn_cache))
            return _tailwind_cdn_cache
    except Exception as exc:
        log.warning("Could not fetch Tailwind CDN for inline export: %s", exc)
        return ""  # export still works, just unstyled
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


# ─── Inventory persistence ────────────────────────────────────────────────────
# inventory.json   → servers, audit results, analysis, settings (no secrets)
# credentials.json → credential profiles with passwords/keys (never exported)

def load_inventory() -> Inventory:
    inv = Inventory()
    if INVENTORY_FILE.is_file():
        try:
            inv = Inventory.model_validate_json(INVENTORY_FILE.read_text())
        except Exception:
            log.warning("inventory.json unreadable — returning empty inventory")

    if CREDENTIALS_FILE.is_file():
        # Load credentials from their dedicated file
        try:
            raw = json.loads(CREDENTIALS_FILE.read_text())
            from models import Credential
            inv.credentials = [Credential(**c) for c in raw.get("credentials", [])]
        except Exception:
            log.warning("credentials.json unreadable")
            inv.credentials = []
    else:
        # One-time migration: move any legacy credentials out of inventory.json
        if inv.credentials:
            _migrate_credentials(inv.credentials)
        inv.credentials = []

    return inv


def _migrate_credentials(creds) -> None:
    """Migrate credentials from legacy inventory.json to credentials.json."""
    CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {"credentials": [c.model_dump() for c in creds]}
    CREDENTIALS_FILE.write_text(json.dumps(payload, indent=2))
    log.info("Migrated %d credential(s) from inventory.json → credentials.json", len(creds))


def save_inventory(inv: Inventory) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    # Persist credentials separately
    cred_payload = {"credentials": [c.model_dump() for c in inv.credentials]}
    CREDENTIALS_FILE.write_text(json.dumps(cred_payload, indent=2))
    # Persist everything else without credentials
    inv_dict = inv.model_dump(exclude={"credentials"})
    INVENTORY_FILE.write_text(json.dumps(inv_dict, indent=2))


# ─── Root ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    index = FRONTEND_DIR / "index.html"
    return HTMLResponse(index.read_text())


# ─── Credentials ─────────────────────────────────────────────────────────────

@app.get("/api/credentials")
async def list_credentials():
    inv = load_inventory()
    # Never return private_key/password in listing
    return [
        {**c.model_dump(exclude={"password", "private_key"}), "has_key": bool(c.private_key), "has_password": bool(c.password)}
        for c in inv.credentials
    ]


@app.post("/api/credentials", status_code=201)
async def create_credential(body: CredentialCreate):
    inv = load_inventory()
    if body.is_default:
        for c in inv.credentials:
            c.is_default = False
    cred = Credential(**body.model_dump())
    inv.credentials.append(cred)
    save_inventory(inv)
    return {"id": cred.id}


@app.put("/api/credentials/{cred_id}")
async def update_credential(cred_id: str, body: CredentialCreate):
    inv = load_inventory()
    idx = next((i for i, c in enumerate(inv.credentials) if c.id == cred_id), None)
    if idx is None:
        raise HTTPException(404, "Credential not found")
    if body.is_default:
        for c in inv.credentials:
            c.is_default = False
    updated = Credential(id=cred_id, **body.model_dump())
    inv.credentials[idx] = updated
    save_inventory(inv)
    return {"ok": True}


@app.delete("/api/credentials/{cred_id}")
async def delete_credential(cred_id: str):
    inv = load_inventory()
    inv.credentials = [c for c in inv.credentials if c.id != cred_id]
    save_inventory(inv)
    return {"ok": True}


# ─── Servers ──────────────────────────────────────────────────────────────────

@app.get("/api/servers")
async def list_servers():
    inv = load_inventory()
    return inv.servers


@app.post("/api/servers", status_code=201)
async def create_server(body: ServerCreate):
    inv = load_inventory()
    srv = Server(**body.model_dump())
    inv.servers.append(srv)
    save_inventory(inv)
    return {"id": srv.id}


@app.put("/api/servers/{server_id}")
async def update_server(server_id: str, body: ServerCreate):
    inv = load_inventory()
    idx = next((i for i, s in enumerate(inv.servers) if s.id == server_id), None)
    if idx is None:
        raise HTTPException(404, "Server not found")
    inv.servers[idx] = Server(id=server_id, **body.model_dump())
    save_inventory(inv)
    return {"ok": True}


@app.delete("/api/servers/{server_id}")
async def delete_server(server_id: str):
    inv = load_inventory()
    inv.servers = [s for s in inv.servers if s.id != server_id]
    save_inventory(inv)
    return {"ok": True}


# ─── Audit ────────────────────────────────────────────────────────────────────

_current_audit: Optional[AuditRun] = None
_current_analysis: Optional[AnalysisResult] = None
_analysis_cancel: list[bool] = [False]


async def _do_audit(audit_run: AuditRun, inv: Inventory) -> None:
    global _current_audit

    def _on_result(r):
        # Append result as soon as an SSH session completes (progressive display)
        audit_run.results.append(r)

    try:
        await run_audit_with_discovery(inv.servers, inv.credentials, on_result=_on_result)
        audit_run.status = "done"
    except Exception:
        log.exception("Audit failed")
        audit_run.status = "error"
    finally:
        audit_run.finished_at = datetime.now(timezone.utc).isoformat()
        # Persist per-node JSON dumps so SVG links can serve them
        DUMPS_DIR.mkdir(exist_ok=True)
        for result in audit_run.results:
            safe_id = re.sub(r"[^\w-]", "-", result.server_id)
            try:
                (DUMPS_DIR / f"{safe_id}.json").write_text(
                    result.model_dump_json(indent=2)
                )
            except Exception:
                log.warning("Failed to save dump for %s", result.server_id)
        # Also save per-discovered-storage-node dumps (healthreport data)
        for result in audit_run.results:
            for sn in result.discovered_storage_nodes:
                sn_safe_id = re.sub(r"[^\w-]", "-", f"disc-storage-{sn.ip}")
                try:
                    (DUMPS_DIR / f"{sn_safe_id}.json").write_text(
                        sn.model_dump_json(indent=2)
                    )
                except Exception:
                    log.warning("Failed to save storage dump for %s", sn.ip)
        inv2 = load_inventory()
        inv2.last_audit = audit_run
        save_inventory(inv2)
        _current_audit = audit_run
        # Trigger AI analysis asynchronously once audit data is saved
        if audit_run.status == "done" and audit_run.results:
            asyncio.create_task(_do_analysis(audit_run.results))


def _get_audit_results() -> list[AuditResult]:
    """Return current or last audit results."""
    if _current_audit and _current_audit.results:
        return _current_audit.results
    inv = load_inventory()
    return inv.last_audit.results if inv.last_audit else []


@app.post("/api/audit/run")
async def trigger_audit(background_tasks: BackgroundTasks):
    global _current_audit
    if _current_audit and _current_audit.status == "running":
        return {"status": "already_running", "audit_id": _current_audit.id}

    inv = load_inventory()
    if not inv.servers:
        raise HTTPException(400, "No servers in inventory")

    audit_run = AuditRun(
        id=str(uuid.uuid4()),
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    _current_audit = audit_run
    background_tasks.add_task(_do_audit, audit_run, inv)
    return {"status": "started", "audit_id": audit_run.id}


@app.get("/api/audit/status")
async def audit_status():
    if _current_audit is None:
        inv = load_inventory()
        if inv.last_audit:
            return inv.last_audit.model_dump(exclude={"results"})
        return {"status": "no_audit"}
    return _current_audit.model_dump(exclude={"results"})


@app.get("/api/audit/results")
async def audit_results():
    if _current_audit and _current_audit.results:
        return _current_audit.results
    inv = load_inventory()
    if inv.last_audit:
        return inv.last_audit.results
    return []


@app.delete("/api/audit")
async def clear_audit():
    global _current_audit
    if _current_audit and _current_audit.status == "running":
        raise HTTPException(409, "Audit is currently running")
    _current_audit = None
    inv = load_inventory()
    inv.last_audit = None
    save_inventory(inv)
    return {"ok": True}


# ─── Discovery (read-only — discovery happens automatically during Run Audit) ──

@app.get("/api/discover/results")
async def discover_results():
    """Return discovered servers from the last audit (is_discovered=True results) + discovery signals."""
    results = _get_audit_results()
    discovered = [r for r in results if r.is_discovered]
    # signals: discovery data from ALL successfully audited servers (seeds + discovered)
    signals = [
        {
            "ip": r.server_ip,
            "name": r.server_name,
            "is_discovered": r.is_discovered,
            "discovered_source": r.discovered_source,
            "roles": [role.role for role in r.roles],
            "keepalived_peers": r.keepalived_peers,
            "haproxy_backends": [{"ip": b.ip, "port": b.port, "name": b.name} for b in r.haproxy_backends],
            "gw_config_path": r.gw_config_path,
            "gw_cluster_ips": r.gw_cluster_ips,
            "gw_es_ips": r.gw_es_ips,
            "gw_lcs_ips": r.gw_lcs_ips,
            "ntp_client_servers": r.ntp_client_servers,
            "syslog_targets": r.syslog_targets,
            "es_seed_hosts": r.es_seed_hosts,
        }
        for r in results
        if r.success
    ]
    return {
        "total_discovered": len(discovered),
        "audit_status": _current_audit.status if _current_audit else "idle",
        "discovered": [
            {
                "ip": r.server_ip,
                "name": r.server_name,
                "source": r.discovered_source,
                "roles": [role.role for role in r.roles],
                "success": r.success,
                "error": r.error,
            }
            for r in discovered
        ],
        "signals": signals,
    }


# ─── Analysis ────────────────────────────────────────────────────────────────

async def _do_analysis(results: list[AuditResult]) -> None:
    global _current_analysis, _analysis_cancel
    inv = load_inventory()
    mcp_url           = os.environ.get("CLAUDE_HUB_MCP_URL", "") or inv.settings.mcp_hub_url
    mcp_token         = os.environ.get("CLAUDE_HUB_MCP_TOKEN", "") or inv.settings.mcp_hub_token
    anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY", "") or inv.settings.anthropic_api_key
    analysis_backend  = inv.settings.analysis_backend  # "auto" | "hub_mcp" | "direct"

    has_direct  = bool(anthropic_api_key)
    has_hub_mcp = bool(mcp_token)
    if not has_direct and not has_hub_mcp:
        log.warning("No analysis credentials configured — skipping AI analysis")
        return
    if analysis_backend == "direct" and not has_direct:
        log.warning("Direct API mode selected but no Anthropic API key — skipping AI analysis")
        return
    if analysis_backend == "hub_mcp" and not has_hub_mcp:
        log.warning("Hub MCP mode selected but no MCP token — skipping AI analysis")
        return

    _analysis_cancel[0] = False
    started = datetime.now(timezone.utc).isoformat()
    _current_analysis = AnalysisResult(status="running", started_at=started)

    def _module_cb(module: AnalysisModule) -> None:
        if _current_analysis and _current_analysis.status == "running":
            _current_analysis.modules.append(module)

    def _progress_cb(msg: str) -> None:
        if _current_analysis and _current_analysis.status == "running":
            _current_analysis.progress = msg

    try:
        result = await run_analysis(
            results, mcp_url, mcp_token, _analysis_cancel, anthropic_api_key, analysis_backend,
            on_module_done=_module_cb, on_progress=_progress_cb,
        )
        result.started_at = started
        result.finished_at = datetime.now(timezone.utc).isoformat()
        _current_analysis = result
        inv2 = load_inventory()
        inv2.last_analysis = result
        save_inventory(inv2)
        log.info("AI analysis complete: %d modules, %d correlations",
                 len(result.modules), len(result.cross_correlations))
    except asyncio.CancelledError:
        _current_analysis.status = "cancelled"
        _current_analysis.finished_at = datetime.now(timezone.utc).isoformat()
    except Exception as exc:
        log.exception("AI analysis failed")
        _current_analysis.status = "error"
        _current_analysis.error = str(exc)
        _current_analysis.finished_at = datetime.now(timezone.utc).isoformat()


@app.get("/api/analysis/status")
async def analysis_status():
    if _current_analysis is not None:
        return _current_analysis.model_dump(exclude={"modules", "cross_correlations"})
    inv = load_inventory()
    if inv.last_analysis:
        return inv.last_analysis.model_dump(exclude={"modules", "cross_correlations"})
    return {"status": "idle"}


@app.get("/api/analysis/results")
async def analysis_results():
    # Return current state even while running (for incremental frontend updates)
    if _current_analysis is not None:
        return _current_analysis
    inv = load_inventory()
    if inv.last_analysis:
        return inv.last_analysis
    return AnalysisResult()


@app.post("/api/analysis/run")
async def retry_analysis():
    """Re-run AI analysis on the last audit results without re-auditing servers."""
    global _current_analysis
    if _current_analysis and _current_analysis.status == "running":
        raise HTTPException(409, "Analysis already running")
    results: list[AuditResult] = []
    if _current_audit and _current_audit.results:
        results = _current_audit.results
    else:
        inv = load_inventory()
        if inv.last_audit:
            results = inv.last_audit.results
    if not results:
        raise HTTPException(404, "No audit results to analyze")
    asyncio.create_task(_do_analysis(results))
    return {"ok": True, "message": "Analysis started"}


@app.delete("/api/analysis")
async def cancel_analysis():
    global _analysis_cancel
    _analysis_cancel[0] = True
    if _current_analysis and _current_analysis.status == "running":
        _current_analysis.status = "cancelled"
        _current_analysis.finished_at = datetime.now(timezone.utc).isoformat()
    return {"ok": True}


@app.get("/api/settings")
async def get_settings():
    inv = load_inventory()
    return {
        "mcp_hub_url":        inv.settings.mcp_hub_url,
        "mcp_hub_token":      inv.settings.mcp_hub_token,
        "has_anthropic_key":  bool(
            os.environ.get("ANTHROPIC_API_KEY") or inv.settings.anthropic_api_key
        ),
        "analysis_backend":   inv.settings.analysis_backend,
    }


@app.put("/api/settings")
async def update_settings(body: dict):
    inv = load_inventory()
    if "mcp_hub_url" in body:
        inv.settings.mcp_hub_url = str(body["mcp_hub_url"])
    if "mcp_hub_token" in body:
        inv.settings.mcp_hub_token = str(body["mcp_hub_token"])
    if "anthropic_api_key" in body:
        inv.settings.anthropic_api_key = str(body["anthropic_api_key"])
    if "analysis_backend" in body and body["analysis_backend"] in ("auto", "hub_mcp", "direct"):
        inv.settings.analysis_backend = body["analysis_backend"]
    save_inventory(inv)
    return {"ok": True}


# ─── Diagram ─────────────────────────────────────────────────────────────────

@app.get("/api/diagram/svg")
async def diagram_svg():
    results: list[AuditResult] = []
    if _current_audit and _current_audit.results:
        results = _current_audit.results
    else:
        inv = load_inventory()
        if inv.last_audit:
            results = inv.last_audit.results

    audit_ts = ""
    if _current_audit and _current_audit.finished_at:
        audit_ts = _current_audit.finished_at[:16].replace("T", " ") + " UTC"
    elif not _current_audit:
        inv2 = load_inventory()
        if inv2.last_audit and inv2.last_audit.finished_at:
            audit_ts = inv2.last_audit.finished_at[:16].replace("T", " ") + " UTC"
    svg = generate_svg(results, collected_at=audit_ts, build=f"v{APP_VERSION}")
    return Response(content=svg, media_type="image/svg+xml")


@app.get("/api/health-report", response_class=HTMLResponse)
async def get_health_report():
    results: list[AuditResult] = []
    if _current_audit and _current_audit.results:
        results = _current_audit.results
    else:
        inv = load_inventory()
        if inv.last_audit:
            results = inv.last_audit.results
    if not results:
        return HTMLResponse("<html><body style='background:#0f0f1e;color:#e2e8f0;font-family:monospace;padding:40px;'>No audit data available.</body></html>")
    html = generate_health_report_html(results)
    return HTMLResponse(html)


def _extract_cluster_name(results: list[AuditResult]) -> str:
    """Best-effort cluster name from audit results — ES cluster name is most reliable."""
    for r in results:
        if r.es_cluster_name:
            return r.es_cluster_name
    return "swarm"


@app.get("/api/export-report")
async def export_report():
    """Self-contained 3-tab HTML report (Diagram / Audit / Analysis) — no backend required."""
    results: list[AuditResult] = []
    if _current_audit and _current_audit.results:
        results = _current_audit.results
    else:
        inv = load_inventory()
        if inv.last_audit:
            results = inv.last_audit.results

    analysis_obj: Optional[AnalysisResult] = None
    if _current_analysis and _current_analysis.status == "done":
        analysis_obj = _current_analysis
    else:
        inv2 = load_inventory()
        if inv2.last_analysis and inv2.last_analysis.status == "done":
            analysis_obj = inv2.last_analysis

    cluster_name = _extract_cluster_name(results)
    now = datetime.now(timezone.utc)
    generated_at = now.strftime("%Y-%m-%d %H:%M UTC")
    date_str = now.strftime("%Y%m%d")
    safe_cluster = re.sub(r"[^a-zA-Z0-9_-]", "-", cluster_name)
    filename = f"arcis-swarm-{safe_cluster}-{date_str}.html"

    svg_content = generate_svg(results, collected_at=generated_at, build=f"v{APP_VERSION}")
    html_content = generate_report_html(results, svg_content, analysis_obj, generated_at, cluster_name)

    return Response(
        content=html_content.encode("utf-8"),
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/inventory")
async def full_inventory():
    return load_inventory()


@app.get("/api/audit/dump/{server_id}")
async def get_node_dump(server_id: str):
    """Serve the per-node JSON dump collected during the last audit."""
    safe_id = re.sub(r"[^\w-]", "-", server_id)
    dump_path = DUMPS_DIR / f"{safe_id}.json"
    if not dump_path.exists():
        raise HTTPException(404, f"No dump available for node '{server_id}'")
    return Response(
        content=dump_path.read_text(),
        media_type="application/json",
        headers={"Content-Disposition": f'inline; filename="{safe_id}.json"'},
    )


@app.get("/api/audit/export")
async def export_audit_json():
    """Return the full last audit payload as a single downloadable JSON."""
    inv = load_inventory()
    if not inv.last_audit:
        return Response(content=json.dumps({"error": "no audit available"}),
                        media_type="application/json", status_code=404)
    content = inv.last_audit.model_dump_json(indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=arcis-swarm-audit.json"},
    )


# ─── Export / Import (servers only — credentials stay in credentials.json) ────

@app.get("/api/export")
async def export_config():
    """Export server inventory only (no credentials, no secrets)."""
    inv = load_inventory()
    payload = {
        "version": "2",
        "servers": [s.model_dump() for s in inv.servers],
    }
    content = json.dumps(payload, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=arcis-swarm-servers.json"},
    )


class ImportBody(PydanticBaseModel):
    version: str = "1"
    credentials: list[dict] = []   # ignored in v2 exports; still accepted for backwards compat
    servers: list[dict] = []
    mode: str = "merge"   # "merge" | "replace"


@app.post("/api/import")
async def import_config(body: ImportBody):
    """Import server inventory. Credentials are never touched by this endpoint."""
    inv = load_inventory()

    if body.mode == "replace":
        inv.servers = []

    existing_srv_ids = {s.id for s in inv.servers}
    imported_srvs = 0

    for raw in body.servers:
        # Strip any credential IDs that won't map to credentials on this instance
        raw.pop("credential_id", None)
        if raw.get("id") and raw["id"] in existing_srv_ids:
            idx = next(i for i, s in enumerate(inv.servers) if s.id == raw["id"])
            inv.servers[idx] = Server(**raw)
        else:
            raw.setdefault("id", str(uuid.uuid4()))
            inv.servers.append(Server(**raw))
            imported_srvs += 1

    save_inventory(inv)
    return {
        "ok": True,
        "imported_servers": imported_srvs,
        "total_servers": len(inv.servers),
    }
