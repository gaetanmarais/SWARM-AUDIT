# Version: 1.0.0
# Date:    2026-06-29
# Notes:   Offline import endpoints — script download with embedded audit.sh,
#           and tar.gz / zip archive import into last_audit

from __future__ import annotations

import base64
import io
import json
import logging
import tarfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, File, HTTPException, Response, UploadFile
from pydantic import ValidationError

from models import AuditResult, AuditRun

log = logging.getLogger(__name__)

# Paths are resolved relative to this file's location
_BACKEND_DIR = Path(__file__).parent
_SCRIPTS_DIR = _BACKEND_DIR.parent / "scripts"

COLLECT_SCRIPT = _SCRIPTS_DIR / "collect_offline.py"
AUDIT_SH       = _SCRIPTS_DIR / "audit.sh"

# 50 MB upload limit
_MAX_UPLOAD_BYTES = 50 * 1024 * 1024

# Magic bytes for format detection
_MAGIC_GZIP = b"\x1f\x8b"
_MAGIC_ZIP  = b"PK\x03\x04"

router = APIRouter()


# ─── GET /api/offline/script ──────────────────────────────────────────────────

@router.get("/api/offline/script")
async def download_offline_script() -> Response:
    """
    Serve collect_offline.py with audit.sh base64-encoded and injected inline.

    Replaces the placeholder line `AUDIT_SH_B64 = ""` with the actual content
    so the downloaded script is fully self-contained — no separate file needed.
    """
    # Read source files — raise 404 with an actionable message on missing file
    try:
        script_bytes = COLLECT_SCRIPT.read_bytes()
    except FileNotFoundError:
        log.error("collect_offline.py not found at %s", COLLECT_SCRIPT)
        raise HTTPException(
            status_code=404,
            detail=f"Collector script not found: {COLLECT_SCRIPT}",
        )
    except OSError as exc:
        log.error("Cannot read collect_offline.py: %s", exc)
        raise HTTPException(status_code=500, detail=f"Cannot read collector script: {exc}")

    try:
        audit_sh_bytes = AUDIT_SH.read_bytes()
    except FileNotFoundError:
        log.error("audit.sh not found at %s", AUDIT_SH)
        raise HTTPException(
            status_code=404,
            detail=f"audit.sh not found: {AUDIT_SH}",
        )
    except OSError as exc:
        log.error("Cannot read audit.sh: %s", exc)
        raise HTTPException(status_code=500, detail=f"Cannot read audit.sh: {exc}")

    # Encode audit.sh and inject into the script
    b64_content = base64.b64encode(audit_sh_bytes).decode("ascii")

    try:
        script_text = script_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        log.error("collect_offline.py is not valid UTF-8: %s", exc)
        raise HTTPException(status_code=500, detail=f"Script encoding error: {exc}")

    # Replace exactly the placeholder line — first occurrence only
    placeholder = 'AUDIT_SH_B64 = ""'
    replacement = f'AUDIT_SH_B64 = "{b64_content}"'

    if placeholder not in script_text:
        log.warning("Placeholder %r not found in collect_offline.py — returning unmodified", placeholder)
    else:
        script_text = script_text.replace(placeholder, replacement, 1)
        log.info(
            "Injected audit.sh (%d bytes → %d chars b64) into collect_offline.py",
            len(audit_sh_bytes), len(b64_content),
        )

    return Response(
        content=script_text.encode("utf-8"),
        media_type="text/x-python",
        headers={
            "Content-Disposition": 'attachment; filename="collect_offline.py"',
            "X-ARCIS-Audit-SH-Size": str(len(audit_sh_bytes)),
        },
    )


# ─── POST /api/import/offline ─────────────────────────────────────────────────

@router.post("/api/import/offline")
async def import_offline_archive(file: UploadFile = File(...)) -> dict:
    """
    Import a collect_offline.py output archive (.tar.gz or .zip) into ARCIS.

    Reads manifest.json and audit_results.json from the archive, validates each
    result against AuditResult, and replaces last_audit in the inventory.

    Returns a summary dict with import counts and metadata.
    """
    # ── Read and size-check the upload ────────────────────────────────────────
    try:
        raw = await file.read()
    except Exception as exc:
        log.error("Failed to read uploaded file: %s", exc)
        raise HTTPException(status_code=500, detail=f"Upload read error: {exc}")

    if len(raw) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"File too large: {len(raw)} bytes (max {_MAX_UPLOAD_BYTES} bytes)",
        )

    if len(raw) < 4:
        raise HTTPException(status_code=400, detail="File is too small to be a valid archive")

    # ── Detect archive format by magic bytes ──────────────────────────────────
    is_gzip = raw[:2] == _MAGIC_GZIP
    is_zip  = raw[:4] == _MAGIC_ZIP

    if not is_gzip and not is_zip:
        raise HTTPException(
            status_code=400,
            detail="Unsupported format. Expected .tar.gz (gzip) or .zip archive.",
        )

    # ── Extract manifest.json and audit_results.json ──────────────────────────
    manifest: Optional[dict] = None
    results_raw: Optional[List] = None

    if is_gzip:
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
                manifest, results_raw = _extract_from_tar(tar)
        except tarfile.TarError as exc:
            log.error("tar.gz extraction failed: %s", exc)
            raise HTTPException(status_code=400, detail=f"tar.gz read error: {exc}")
        except Exception as exc:
            log.error("Unexpected error reading tar.gz: %s", exc)
            raise HTTPException(status_code=500, detail=f"Archive read error: {exc}")

    else:  # zip
        try:
            with zipfile.ZipFile(io.BytesIO(raw), "r") as zf:
                manifest, results_raw = _extract_from_zip(zf)
        except zipfile.BadZipFile as exc:
            log.error("zip extraction failed: %s", exc)
            raise HTTPException(status_code=400, detail=f"zip read error: {exc}")
        except Exception as exc:
            log.error("Unexpected error reading zip: %s", exc)
            raise HTTPException(status_code=500, detail=f"Archive read error: {exc}")

    # ── Validate extracted content ─────────────────────────────────────────────
    if manifest is None:
        raise HTTPException(
            status_code=400,
            detail="Archive does not contain manifest.json",
        )

    archive_format = manifest.get("format", "")
    if not archive_format.startswith("arcis-offline"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported archive format: {archive_format!r} (expected 'arcis-offline-v1')",
        )

    if results_raw is None:
        raise HTTPException(
            status_code=400,
            detail="Archive does not contain audit_results.json",
        )

    if not isinstance(results_raw, list):
        raise HTTPException(
            status_code=400,
            detail="audit_results.json must be a JSON array",
        )

    # ── Validate each result with AuditResult ─────────────────────────────────
    collected_at = manifest.get("collected_at") or datetime.now(timezone.utc).isoformat()
    cluster_name = manifest.get("cluster_name", "")

    validated_results: List[AuditResult] = []
    skipped = 0
    error_msgs: List[str] = []

    for idx, raw_result in enumerate(results_raw):
        if not isinstance(raw_result, dict):
            skipped += 1
            msg = f"Entry {idx}: not a dict (got {type(raw_result).__name__})"
            log.warning("import_offline: %s — skipping", msg)
            if len(error_msgs) < 10:
                error_msgs.append(msg)
            continue

        try:
            validated_results.append(AuditResult.model_validate(raw_result))
        except ValidationError as exc:
            skipped += 1
            ip = raw_result.get("server_ip", f"entry#{idx}")
            # Summarise the first validation error to keep the response readable
            first_err = exc.errors()[0] if exc.errors() else {}
            msg = f"{ip}: validation error — {first_err.get('loc', '')} {first_err.get('msg', exc)}"
            log.warning("import_offline: %s — skipping", msg)
            if len(error_msgs) < 10:
                error_msgs.append(msg)
        except Exception as exc:
            skipped += 1
            ip = raw_result.get("server_ip", f"entry#{idx}")
            msg = f"{ip}: unexpected error — {exc}"
            log.error("import_offline: %s", msg)
            if len(error_msgs) < 10:
                error_msgs.append(msg)

    imported_count = len(validated_results)
    log.info(
        "import_offline: %d imported, %d skipped from %s",
        imported_count, skipped, file.filename or "<upload>",
    )

    # ── Build AuditRun and persist ─────────────────────────────────────────────
    audit_run = AuditRun(
        id=str(uuid.uuid4()),
        started_at=collected_at,
        finished_at=collected_at,
        status="done",
        results=validated_results,
    )

    try:
        # Import load/save from main — lazy import to avoid circular dependency at module load
        from main import load_inventory, save_inventory  # noqa: PLC0415
        inv = load_inventory()
        inv.last_audit = audit_run
        inv.last_analysis = None   # stale analysis no longer matches new audit
        save_inventory(inv)
        log.info("import_offline: inventory updated — last_audit replaced")
    except Exception as exc:
        log.error("import_offline: failed to persist inventory: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to save inventory: {exc}")

    return {
        "ok": True,
        "imported": imported_count,
        "skipped": skipped,
        "errors": error_msgs,
        "collected_at": collected_at,
        "cluster": cluster_name,
    }


# ─── Archive extraction helpers ───────────────────────────────────────────────

def _read_json_member(data: bytes, member_name: str) -> object:
    """
    Parse bytes as JSON. Raises HTTPException 400 on malformed JSON.
    member_name is used only for the error message.
    """
    try:
        return json.loads(data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"{member_name} contains invalid JSON: {exc}",
        ) from exc


def _extract_from_tar(
    tar: tarfile.TarFile,
) -> tuple:
    """
    Extract manifest.json and audit_results.json from an open TarFile.
    Returns (manifest_dict | None, results_list | None).
    """
    manifest: Optional[dict] = None
    results_raw = None

    for member in tar.getmembers():
        name = member.name.lstrip("./")
        if name not in ("manifest.json", "audit_results.json"):
            continue
        try:
            fh = tar.extractfile(member)
            if fh is None:
                continue
            data = fh.read()
        except Exception as exc:
            raise HTTPException(
                status_code=400, detail=f"Cannot read {name} from archive: {exc}"
            ) from exc

        parsed = _read_json_member(data, name)
        if name == "manifest.json":
            if not isinstance(parsed, dict):
                raise HTTPException(status_code=400, detail="manifest.json must be a JSON object")
            manifest = parsed
        else:
            results_raw = parsed

        if manifest is not None and results_raw is not None:
            break

    return manifest, results_raw


def _extract_from_zip(
    zf: zipfile.ZipFile,
) -> tuple:
    """
    Extract manifest.json and audit_results.json from an open ZipFile.
    Returns (manifest_dict | None, results_list | None).
    """
    manifest: Optional[dict] = None
    results_raw = None

    for info in zf.infolist():
        name = info.filename.lstrip("./")
        if name not in ("manifest.json", "audit_results.json"):
            continue
        try:
            data = zf.read(info.filename)
        except Exception as exc:
            raise HTTPException(
                status_code=400, detail=f"Cannot read {name} from zip: {exc}"
            ) from exc

        parsed = _read_json_member(data, name)
        if name == "manifest.json":
            if not isinstance(parsed, dict):
                raise HTTPException(status_code=400, detail="manifest.json must be a JSON object")
            manifest = parsed
        else:
            results_raw = parsed

        if manifest is not None and results_raw is not None:
            break

    return manifest, results_raw
