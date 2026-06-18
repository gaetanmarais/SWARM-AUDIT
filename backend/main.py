# Version: 1.6.0
# Date:    2026-06-18
# Notes:   export-report: single self-contained index.html with embedded data + fetch interception

from __future__ import annotations
import asyncio
import io
import json
import logging
import re
import zipfile
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
)
from audit import run_audit
from svg_gen import generate_svg
from health_report import generate_health_report_html

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

INVENTORY_FILE = Path(__file__).parent.parent / "inventory.json"
FRONTEND_DIR   = Path(__file__).parent.parent / "frontend"
DUMPS_DIR      = Path(__file__).parent.parent / "dumps"

app = FastAPI(title="ARCIS-SWARM", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


# ─── Inventory persistence ────────────────────────────────────────────────────

def load_inventory() -> Inventory:
    if INVENTORY_FILE.exists():
        return Inventory.model_validate_json(INVENTORY_FILE.read_text())
    return Inventory()


def save_inventory(inv: Inventory) -> None:
    INVENTORY_FILE.write_text(inv.model_dump_json(indent=2))


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


async def _do_audit(audit_run: AuditRun, inv: Inventory) -> None:
    global _current_audit

    def _on_result(r):
        # Append result as soon as an SSH session completes (progressive display)
        audit_run.results.append(r)

    try:
        await run_audit(inv.servers, inv.credentials, on_result=_on_result)
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

    svg = generate_svg(results)
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


@app.get("/api/export-report")
async def export_report():
    """ZIP containing a self-contained index.html that mirrors the live SPA (read-only)."""
    results: list[AuditResult] = []
    if _current_audit and _current_audit.results:
        results = _current_audit.results
    else:
        inv = load_inventory()
        if inv.last_audit:
            results = inv.last_audit.results

    svg_content = generate_svg(results)

    # Serialize results without credentials/server-management sensitive fields
    results_json = json.dumps(
        [r.model_dump() for r in results],
        ensure_ascii=False, default=str,
    )

    # Read the SPA source
    spa_path = Path(__file__).parent.parent / "frontend" / "index.html"
    spa_html = spa_path.read_text(encoding="utf-8")

    # Build the fetch-interception + embedded-data script injected just before init()
    # This makes the exported HTML fully standalone: no API calls needed.
    inject_js = f"""
// ── STATIC EXPORT — read-only, no backend required ───────────────────────────
const _EXPORT_DATA = {{
  results: {results_json},
  svg:     {json.dumps(svg_content)},
}};
(function () {{
  const _realFetch = window.fetch.bind(window);
  window.fetch = function (url, opts) {{
    const method = (opts && opts.method || 'GET').toUpperCase();
    const u = typeof url === 'string' ? url : url.toString();
    // Block all write operations silently
    if (method !== 'GET') {{
      return Promise.resolve({{
        ok: false, status: 403,
        json: () => Promise.resolve({{ error: 'read-only export' }}),
        text: () => Promise.resolve(''),
      }});
    }}
    if (u.includes('/api/audit/results'))
      return Promise.resolve({{ ok: true, json: () => Promise.resolve(_EXPORT_DATA.results) }});
    if (u.includes('/api/diagram/svg'))
      return Promise.resolve({{ ok: true, text: () => Promise.resolve(_EXPORT_DATA.svg) }});
    if (u.includes('/api/credentials'))
      return Promise.resolve({{ ok: true, json: () => Promise.resolve([]) }});
    if (u.includes('/api/servers'))
      return Promise.resolve({{ ok: true, json: () => Promise.resolve([]) }});
    if (u.includes('/api/audit/status'))
      return Promise.resolve({{ ok: true, json: () => Promise.resolve({{ status: 'idle' }}) }});
    return _realFetch(url, opts);
  }};

  // After DOM ready: hide all write-only UI elements
  document.addEventListener('DOMContentLoaded', function () {{
    // Hide Run Audit button, Add Credential/Server forms, import/clear buttons
    const hideSelectors = [
      '#run-audit-btn', '#add-credential-form', '#add-server-form',
      '#clear-audit-btn', '#import-btn',
    ];
    hideSelectors.forEach(function (sel) {{
      const el = document.querySelector(sel);
      if (el) el.style.display = 'none';
    }});
    // Read-only banner
    const banner = document.createElement('div');
    banner.style.cssText = 'position:fixed;top:0;left:0;right:0;background:#1e3a5f;color:#93c5fd;' +
      'font-size:11px;text-align:center;padding:3px 0;z-index:9999;letter-spacing:.05em;' +
      'border-bottom:1px solid #2563eb;';
    banner.textContent = 'ARCIS-SWARM — Rapport statique (lecture seule)';
    document.body.prepend(banner);
  }});
}})();
// ─────────────────────────────────────────────────────────────────────────────
"""

    # Inject just before the closing </script></body></html>
    marker = "init();\n</script>"
    if marker in spa_html:
        exported_html = spa_html.replace(marker, inject_js + "\ninit();\n</script>")
    else:
        # Fallback: inject before </body>
        exported_html = spa_html.replace("</body>", f"<script>{inject_js}</script></body>")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.html", exported_html.encode("utf-8"))
    buf.seek(0)

    return Response(
        content=buf.read(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="arcis-swarm-report.zip"'},
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


# ─── Export / Import ──────────────────────────────────────────────────────────

@app.get("/api/export")
async def export_config():
    """Export servers + credential profiles without any secrets (password/key)."""
    inv = load_inventory()
    payload = {
        "version": "1",
        "credentials": [
            {k: v for k, v in c.model_dump().items()
             if k not in ("password", "private_key")}
            for c in inv.credentials
        ],
        "servers": [s.model_dump() for s in inv.servers],
    }
    content = json.dumps(payload, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=arcis-swarm-config.json"},
    )


class ImportBody(PydanticBaseModel):
    version: str = "1"
    credentials: list[dict] = []
    servers: list[dict] = []
    mode: str = "merge"   # "merge" | "replace"


@app.post("/api/import")
async def import_config(body: ImportBody):
    """Import servers and credential profiles. Secrets are never imported."""
    inv = load_inventory()

    if body.mode == "replace":
        inv.credentials = []
        inv.servers = []

    existing_cred_ids = {c.id for c in inv.credentials}
    existing_srv_ids  = {s.id for s in inv.servers}

    imported_creds = 0
    imported_srvs  = 0

    for raw in body.credentials:
        # Strip secrets even if caller accidentally included them
        raw.pop("password", None)
        raw.pop("private_key", None)
        if raw.get("id") and raw["id"] in existing_cred_ids:
            # Update metadata only (not secrets)
            idx = next(i for i, c in enumerate(inv.credentials) if c.id == raw["id"])
            for field in ("name", "username", "port", "is_default"):
                if field in raw:
                    setattr(inv.credentials[idx], field, raw[field])
        else:
            raw.setdefault("id", str(uuid.uuid4()))
            inv.credentials.append(Credential(**raw))
            imported_creds += 1

    for raw in body.servers:
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
        "imported_credentials": imported_creds,
        "imported_servers": imported_srvs,
        "total_credentials": len(inv.credentials),
        "total_servers": len(inv.servers),
    }
