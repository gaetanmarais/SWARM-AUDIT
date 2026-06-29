#!/usr/bin/env python3
# Version: 1.0.0
# Date:    2026-06-29
# Notes:   Standalone offline collector — SSH multi-wave discovery via paramiko,
#           generates a tar.gz importable by ARCIS /api/import/offline

"""
ARCIS-SWARM Offline Collector
==============================

Run this script on any machine that has SSH access to the cluster nodes.
It replicates the multi-wave discovery logic of the ARCIS backend without
requiring network access to the ARCIS server itself.

Usage
-----
Interactive mode (prompts for seeds, credentials, options):
    python3 collect_offline.py

CLI mode (no prompts):
    python3 collect_offline.py \\
        --seeds 10.0.0.1,10.0.0.2 \\
        --user root --password s3cr3t --port 22 \\
        --max-waves 4 --output-dir /tmp

CLI mode with SSH key:
    python3 collect_offline.py \\
        --seeds 10.0.0.1 \\
        --user root --key ~/.ssh/id_rsa \\
        --no-interactive

Output
------
Generates a .tar.gz archive containing:
  - manifest.json       : collection metadata
  - audit_results.json  : list of AuditResult-compatible dicts
  - nodes/<ip>.json     : per-node raw result

Import into ARCIS:
  POST /api/import/offline  (multipart, field name: "file")

Requirements
------------
  pip install paramiko
"""

# ─── AUDIT_SH_B64 placeholder ─────────────────────────────────────────────────
# When downloaded from ARCIS GET /api/offline/script, this line is replaced
# with the actual base64-encoded audit.sh. If empty at runtime, the script
# looks for audit.sh in the same directory.
AUDIT_SH_B64 = ""

# ─── Dependency check (must be first import) ──────────────────────────────────
import sys

try:
    import paramiko
except ImportError:
    print(
        "ERROR: paramiko is not installed.\n"
        "  Install it with:  pip install paramiko\n"
        "  Or:               pip3 install paramiko",
        file=sys.stderr,
    )
    sys.exit(1)

# ─── Standard library imports ─────────────────────────────────────────────────
import argparse
import base64
import getpass
import io
import json
import logging
import os
import socket
import tarfile
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ─── Constants ────────────────────────────────────────────────────────────────
VERSION            = "1.1.0"
SSH_CONNECT_TIMEOUT = 20    # seconds — TCP + handshake + auth
SCRIPT_TIMEOUT     = 600    # seconds — audit.sh max execution time
MAX_WAVES          = 4      # default multi-wave depth
MAX_WORKERS        = 10     # concurrent SSH threads
# Max simultaneous SSH connections through the same jump host.
# sshd defaults: MaxStartups=10:30:100, MaxSessions=10 — stay well below.
MAX_CONCURRENT_PER_JUMP = 4

# ─── ANSI helpers ─────────────────────────────────────────────────────────────
_IS_TTY = hasattr(sys.stderr, "isatty") and sys.stderr.isatty()

def _c(code: str, text: str) -> str:
    """Wrap text in ANSI color code if stderr is a TTY."""
    if not _IS_TTY:
        return text
    return f"\033[{code}m{text}\033[0m"

def _ok(msg: str) -> str:   return _c("32", f"[OK]   {msg}")
def _fail(msg: str) -> str: return _c("31", f"[FAIL] {msg}")
def _skip(msg: str) -> str: return _c("33", f"[SKIP] {msg}")
def _info(msg: str) -> str: return _c("36", f"[INFO] {msg}")

# ─── Per-jump-host concurrency control ────────────────────────────────────────
# Multiple threads jumping through the same host saturate sshd MaxStartups.
# One semaphore per jump IP caps simultaneous tunnel openings.
_jump_sem_registry: Dict[str, threading.Semaphore] = {}
_jump_sem_registry_lock = threading.Lock()

def _jump_semaphore(jump_ip: str) -> threading.Semaphore:
    with _jump_sem_registry_lock:
        if jump_ip not in _jump_sem_registry:
            _jump_sem_registry[jump_ip] = threading.Semaphore(MAX_CONCURRENT_PER_JUMP)
        return _jump_sem_registry[jump_ip]

# ─── Logging setup ────────────────────────────────────────────────────────────
# All progress goes to stderr so stdout remains clean for piping.
_log_lock = threading.Lock()

class _StderrFormatter(logging.Formatter):
    """Timestamp + level prefix, ANSI-colored by level when TTY."""
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.now().strftime("%H:%M:%S")
        lvl = record.levelname
        msg = record.getMessage()
        if _IS_TTY:
            if record.levelno >= logging.ERROR:
                lvl = _c("31", lvl)
            elif record.levelno >= logging.WARNING:
                lvl = _c("33", lvl)
            else:
                lvl = _c("36", lvl)
        return f"{ts} {lvl:20s} {msg}"

_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(_StderrFormatter())
logging.basicConfig(level=logging.INFO, handlers=[_handler])
log = logging.getLogger("arcis.offline")


# ─── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class Credential:
    """SSH credential profile. Mirrors the backend Credential model."""
    name: str
    username: str
    password: Optional[str] = None
    private_key_path: Optional[str] = None
    port: int = 22
    is_default: bool = False


@dataclass
class Candidate:
    """A discovered candidate IP to probe in the next wave."""
    ip: str
    source: str           # keepalived_peer|haproxy_backend|gw_cluster|gw_es|gw_lcs|ntp_target|syslog_target|es_seed|swarmctl_storage
    hint_role: str = ""
    jump_host_ip: str = ""


# ─── Audit script loader ──────────────────────────────────────────────────────

def _get_audit_script() -> bytes:
    """
    Return the audit.sh bytes.
    Priority: AUDIT_SH_B64 (injected by ARCIS at download time) → local audit.sh.
    Raises RuntimeError with a clear message if neither is available.
    """
    if AUDIT_SH_B64.strip():
        try:
            return base64.b64decode(AUDIT_SH_B64)
        except Exception as exc:
            raise RuntimeError(f"AUDIT_SH_B64 is set but cannot be decoded: {exc}") from exc

    # Fall back to a local audit.sh in the same directory as this script
    local_path = Path(__file__).parent / "audit.sh"
    if local_path.is_file():
        log.info(_info(f"AUDIT_SH_B64 is empty — loading local {local_path}"))
        return local_path.read_bytes()

    raise RuntimeError(
        "audit.sh not found. Either:\n"
        "  1. Download this script from ARCIS at GET /api/offline/script (embeds audit.sh)\n"
        "  2. Place audit.sh in the same directory as this script"
    )


# ─── SSH helpers ──────────────────────────────────────────────────────────────

def _load_private_key(path: str) -> paramiko.PKey:
    """
    Load a private key from path, trying all supported key types.
    Raises ValueError with a clear message if no type matches.
    """
    key_types = [
        ("RSA",     paramiko.RSAKey),
        ("Ed25519", paramiko.Ed25519Key),
        ("ECDSA",   paramiko.ECDSAKey),
        ("DSS",     paramiko.DSSKey),
    ]
    last_exc: Optional[Exception] = None
    for type_name, key_cls in key_types:
        try:
            return key_cls.from_private_key_file(path)
        except paramiko.ssh_exception.PasswordRequiredException:
            # Key is passphrase-protected — prompt once
            passphrase = getpass.getpass(f"Passphrase for {path}: ")
            try:
                return key_cls.from_private_key_file(path, password=passphrase)
            except Exception as exc:
                last_exc = exc
        except Exception as exc:
            last_exc = exc

    raise ValueError(
        f"Cannot load private key from '{path}'. Tried: {[n for n, _ in key_types]}. "
        f"Last error: {last_exc}"
    )


def _open_ssh(
    ip: str,
    port: int,
    cred: Credential,
    sock: Optional[paramiko.Channel] = None,
) -> paramiko.SSHClient:
    """
    Open a paramiko SSH connection to ip:port using cred.
    If sock is provided (jump-channel), it is used as the transport socket.
    Returns connected SSHClient. The caller must close it.
    Raises on any failure (paramiko.SSHException, socket.error, etc.).
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs: Dict = {
        "hostname": ip,
        "port": port,
        "username": cred.username,
        "timeout": SSH_CONNECT_TIMEOUT,
        "banner_timeout": SSH_CONNECT_TIMEOUT,
        "auth_timeout": SSH_CONNECT_TIMEOUT,
        "allow_agent": False,
        "look_for_keys": False,
    }

    if sock is not None:
        connect_kwargs["sock"] = sock

    if cred.private_key_path:
        try:
            pkey = _load_private_key(cred.private_key_path)
        except ValueError as exc:
            raise paramiko.AuthenticationException(str(exc)) from exc
        connect_kwargs["pkey"] = pkey
    elif cred.password is not None:
        connect_kwargs["password"] = cred.password
    else:
        raise ValueError(
            f"Credential '{cred.name}' has neither password nor private_key_path"
        )

    client.connect(**connect_kwargs)
    return client


def _open_jump_channel(
    jump_ip: str,
    jump_port: int,
    jump_cred: Credential,
    target_ip: str,
    target_port: int,
) -> Tuple[paramiko.SSHClient, paramiko.Channel]:
    """
    Open an SSH connection to jump_ip, then create a direct-tcpip channel
    to target_ip:target_port through it.
    Returns (jump_client, channel). Both must be closed by the caller.
    Raises on any failure.
    """
    jump_client = _open_ssh(jump_ip, jump_port, jump_cred)
    try:
        transport = jump_client.get_transport()
        if transport is None:
            raise RuntimeError(f"Jump host {jump_ip}: no transport after connect")
        channel = transport.open_channel(
            "direct-tcpip",
            (target_ip, target_port),
            ("127.0.0.1", 0),
        )
    except Exception:
        jump_client.close()
        raise

    return jump_client, channel


# ─── Node auditor ─────────────────────────────────────────────────────────────

def _run_audit_script(
    client: paramiko.SSHClient,
    ip: str,
    audit_sh: bytes,
) -> dict:
    """
    Upload audit.sh to the remote node via SFTP, execute it, parse JSON output.
    Cleans up the remote temp file in all cases (finally block).
    Returns a dict. On failure, returns {"success": False, "error": "<message>"}.
    """
    remote_path = f"/tmp/_arcis_offline_{uuid.uuid4().hex[:8]}.sh"
    uploaded = False

    try:
        # Upload via SFTP
        try:
            sftp = client.open_sftp()
        except Exception as exc:
            log.error(_fail(f"{ip}: SFTP open failed: {exc}"))
            return {"success": False, "error": f"SFTP open: {exc}"}

        try:
            with sftp.open(remote_path, "wb") as fh:
                fh.write(audit_sh)
            uploaded = True
            log.info(_info(f"{ip}: uploaded {len(audit_sh)} bytes → {remote_path}"))
        except Exception as exc:
            log.error(_fail(f"{ip}: SFTP write to {remote_path} failed: {exc}"))
            return {"success": False, "error": f"SFTP write: {exc}"}
        finally:
            try:
                sftp.close()
            except Exception:
                pass

        # chmod +x
        try:
            _, stdout, stderr = client.exec_command(f'chmod +x -- "{remote_path}"')
            stdout.channel.recv_exit_status()
        except Exception as exc:
            log.error(_fail(f"{ip}: chmod failed: {exc}"))
            return {"success": False, "error": f"chmod: {exc}"}

        # Execute with timeout via a background thread reading stdout
        try:
            _, stdout, stderr = client.exec_command(
                f'bash -- "{remote_path}"',
                timeout=SCRIPT_TIMEOUT,
            )
        except Exception as exc:
            log.error(_fail(f"{ip}: exec_command failed: {exc}"))
            return {"success": False, "error": f"exec_command: {exc}"}

        # Read stdout (may be large — swarmctl data)
        try:
            raw_out = stdout.read()
        except Exception as exc:
            log.error(_fail(f"{ip}: stdout read failed: {exc}"))
            return {"success": False, "error": f"stdout read: {exc}"}

        try:
            exit_code = stdout.channel.recv_exit_status()
        except Exception as exc:
            log.warning(f"{ip}: could not read exit code: {exc}")
            exit_code = 0

        if exit_code != 0:
            try:
                err_msg = stderr.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                err_msg = "(stderr unreadable)"
            log.error(_fail(f"{ip}: script exited {exit_code}: {err_msg}"))
            return {"success": False, "error": f"Script exit {exit_code}: {err_msg}"}

        # Parse JSON
        raw_str = raw_out.decode("utf-8", errors="replace").strip()
        if not raw_str:
            log.error(_fail(f"{ip}: empty script output"))
            return {"success": False, "error": "Empty script output"}

        try:
            data = json.loads(raw_str)
        except json.JSONDecodeError as exc:
            char = exc.pos or 0
            snippet = raw_str[max(0, char - 40): char + 40]
            log.error(
                _fail(f"{ip}: JSON parse error at char {char}: {exc} | near: {snippet!r}")
            )
            return {"success": False, "error": f"JSON parse error: {exc}"}

        log.info(_ok(f"{ip}: audit script returned {len(raw_str)} bytes of JSON"))
        return data

    finally:
        # Best-effort cleanup — always attempt, never raise
        if uploaded:
            try:
                _, rm_out, _ = client.exec_command(
                    f'[ -n "{remote_path}" ] && rm -f -- "{remote_path}"'
                )
                rm_out.channel.recv_exit_status()
                log.info(_info(f"{ip}: cleaned up {remote_path}"))
            except Exception as exc:
                log.warning(f"{ip}: cleanup of {remote_path} failed (non-fatal): {exc}")


def _audit_node(
    ip: str,
    port: int,
    creds: List[Credential],
    audit_sh: bytes,
    jump_ip: str = "",
    jump_creds: Optional[List[Credential]] = None,
) -> dict:
    """
    Audit a single node: try each credential in order, optionally via a jump host.
    Returns an AuditResult-compatible dict with at minimum:
      server_id, server_name, server_ip, success, error, is_discovered, discovered_source.
    """
    if not creds:
        log.error(_fail(f"{ip}: no credentials available"))
        return _make_error_result(ip, ip, "No credential available")

    effective_jump_creds = jump_creds or creds

    # Establish jump host connection once (shared across cred attempts on target)
    jump_client: Optional[paramiko.SSHClient] = None
    jump_channel: Optional[paramiko.Channel] = None

    if jump_ip:
        jump_opened = False
        # Acquire per-jump-host slot to avoid saturating sshd MaxStartups
        sem = _jump_semaphore(jump_ip)
        sem.acquire()
        try:
            for jcred in effective_jump_creds:
                try:
                    jump_client, jump_channel = _open_jump_channel(
                        jump_ip, jcred.port, jcred, ip, port
                    )
                    log.info(_info(f"{ip}: jump via {jump_ip} opened with cred '{jcred.name}'"))
                    jump_opened = True
                    break
                except Exception as exc:
                    log.info(f"  {ip}: jump host {jump_ip} cred '{jcred.name}' failed: {exc}")
        finally:
            sem.release()

        if not jump_opened:
            log.error(_fail(f"{ip}: jump host {jump_ip} unreachable (tried {len(effective_jump_creds)} cred(s))"))
            return _make_error_result(
                ip, ip, f"Jump host {jump_ip} unreachable (tried {len(effective_jump_creds)} cred(s))"
            )

    try:
        last_error: str = "No credential available"
        for cred in creds:
            client: Optional[paramiko.SSHClient] = None
            try:
                log.info(_info(f"{ip}: trying cred '{cred.name}' (jump={jump_ip or 'none'})"))
                client = _open_ssh(ip, port, cred, sock=jump_channel)
                data = _run_audit_script(client, ip, audit_sh)
                if not data.get("success", True) and "error" in data:
                    # Script-level failure (non-auth) — don't retry with other creds
                    log.warning(_fail(f"{ip}: script error (cred '{cred.name}'): {data['error']}"))
                    return _build_result(ip, data)
                # Success
                log.info(_ok(f"{ip}: audit complete via cred '{cred.name}'"))
                return _build_result(ip, data)

            except (paramiko.AuthenticationException, paramiko.BadAuthenticationType) as exc:
                last_error = f"Auth failed with cred '{cred.name}': {exc}"
                log.info(f"  {ip}: {last_error} — trying next cred")
            except (paramiko.SSHException, socket.error, OSError) as exc:
                err_str = str(exc)
                last_error = f"SSH/network error with cred '{cred.name}': {exc}"
                log.info(f"  {ip}: {last_error}")
                # connect timeout or unreachable — no point trying other creds
                if "timed out" in err_str.lower() or "connection refused" in err_str.lower():
                    break
            except Exception as exc:
                last_error = f"Unexpected error with cred '{cred.name}': {exc}"
                log.error(_fail(f"{ip}: {last_error}"))
            finally:
                if client is not None:
                    try:
                        client.close()
                    except Exception:
                        pass

        log.error(_fail(f"{ip}: all credentials exhausted — last error: {last_error}"))
        return _make_error_result(ip, ip, last_error)

    finally:
        # Close jump channel and client regardless of outcome
        if jump_channel is not None:
            try:
                jump_channel.close()
            except Exception:
                pass
        if jump_client is not None:
            try:
                jump_client.close()
            except Exception:
                pass


def _make_error_result(ip: str, name: str, error: str) -> dict:
    """
    Build a minimal AuditResult-compatible dict for a failed node.
    All list/dict fields default to empty to match AuditResult defaults.
    """
    return {
        "server_id": str(uuid.uuid4()),
        "server_name": name or ip,
        "server_ip": ip,
        "success": False,
        "error": error,
        "is_discovered": False,
        "discovered_source": "",
        "hostname": None, "os": None, "kernel": None, "uptime_sec": None,
        "cpu": None, "ram": None,
        "disks": [], "roles": [], "network_interfaces": [],
        "config_files": [], "config_contents": {}, "installed_packages": [],
        "haproxy_backends": [], "haproxy_vips": [],
        "gw_config_path": "", "gw_cluster_ips": [], "gw_es_ips": [], "gw_lcs_ips": [],
        "swarm_cluster_summary": "", "discovered_storage_nodes": [],
        "es_cluster_name": "", "discovered_es_nodes": [], "es_seed_hosts": [],
        "es_cat_health": "", "es_cat_indices": "", "es_cat_nodes": "",
        "es_node_stats": "", "es_cat_alloc": "", "es_disk_info": None,
        "health_report_json": None,
        "is_syslog_server": False, "is_ntp_server": False,
        "is_dhcp_server": False, "is_pxe_server": False,
        "is_rabbitmq": False, "is_prometheus": False,
        "is_alertmanager": False, "is_grafana": False,
        "is_s3": False, "is_content_ui": False, "is_storage_ui": False,
        "ntp_client_servers": [], "syslog_targets": [], "keepalived_peers": [],
        "listen_ports": [], "connections": [], "logs": {},
        "swarmctl_feeds": None,
    }


def _build_result(ip: str, data: dict) -> dict:
    """
    Merge audit.sh JSON output into a full AuditResult-compatible dict.
    Fills in server_id, server_name, server_ip and all defaults for missing fields.
    """
    base = _make_error_result(ip, data.get("hostname") or ip, None)  # type: ignore[arg-type]
    # Overwrite with actual data from audit.sh
    base.update({
        "success": True,
        "error": None,
        "hostname": data.get("hostname"),
        "os": data.get("os"),
        "kernel": data.get("kernel"),
        "uptime_sec": data.get("uptime_sec"),
        "cpu": data.get("cpu"),
        "ram": data.get("ram"),
        "disks": data.get("disks", []),
        "roles": data.get("roles", []),
        "network_interfaces": data.get("network_interfaces", []),
        "config_files": data.get("config_files", []),
        "config_contents": data.get("config_contents", {}),
        "installed_packages": data.get("installed_packages", []),
        "haproxy_backends": data.get("haproxy_backends", []),
        "haproxy_vips": data.get("haproxy_vips", []),
        "gw_config_path": data.get("gw_config_path", ""),
        "gw_cluster_ips": data.get("gw_cluster_ips", []),
        "gw_es_ips": data.get("gw_es_ips", []),
        "gw_lcs_ips": data.get("gw_lcs_ips", []),
        "swarm_cluster_summary": data.get("swarm_cluster_summary", ""),
        "discovered_storage_nodes": data.get("discovered_storage_nodes", []),
        "es_cluster_name": data.get("es_cluster_name", ""),
        "discovered_es_nodes": data.get("discovered_es_nodes", []),
        "es_seed_hosts": data.get("es_seed_hosts", []),
        "es_cat_health": data.get("es_cat_health", ""),
        "es_cat_indices": data.get("es_cat_indices", ""),
        "es_cat_nodes": data.get("es_cat_nodes", ""),
        "es_node_stats": data.get("es_node_stats", ""),
        "es_cat_alloc": data.get("es_cat_alloc", ""),
        "es_disk_info": data.get("es_disk_info"),
        "health_report_json": data.get("health_report_json"),
        "is_syslog_server": data.get("is_syslog_server", False),
        "is_ntp_server": data.get("is_ntp_server", False),
        "is_dhcp_server": data.get("is_dhcp_server", False),
        "is_pxe_server": data.get("is_pxe_server", False),
        "is_rabbitmq": data.get("is_rabbitmq", False),
        "is_prometheus": data.get("is_prometheus", False),
        "is_alertmanager": data.get("is_alertmanager", False),
        "is_grafana": data.get("is_grafana", False),
        "is_s3": data.get("is_s3", False),
        "is_content_ui": data.get("is_content_ui", False),
        "is_storage_ui": data.get("is_storage_ui", False),
        "ntp_client_servers": data.get("ntp_client_servers", []),
        "syslog_targets": data.get("syslog_targets", []),
        "keepalived_peers": data.get("keepalived_peers", []),
        "listen_ports": data.get("listen_ports", []),
        "connections": data.get("connections", []),
        "logs": data.get("logs", {}),
        "swarmctl_feeds": data.get("swarmctl_feeds"),
    })
    # server_name: prefer FQDN hostname if audit returned one
    if data.get("hostname"):
        base["server_name"] = data["hostname"]
    return base


# ─── Candidate extraction ─────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    """True for RFC1918, link-local, and loopback ranges."""
    if ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("169.254."):
        return True
    if ip.startswith("127."):
        return True
    if ip in ("0.0.0.0", "::1"):
        return True
    try:
        third = int(ip.split(".")[1]) if ip.count(".") >= 1 else -1
        if ip.startswith("172.") and 16 <= third <= 31:
            return True
    except (ValueError, IndexError):
        pass
    return False


def extract_candidates(result: dict, known_ips: set) -> List[Candidate]:
    """
    Extract new candidate IPs from an audit result.

    Same routing logic as audit.py extract_candidate_ips:
    - keepalived_peers / haproxy_backends: direct (same L2 segment)
    - gw_cluster / gw_es / gw_lcs: jump via node_ip (private subnet behind GW)
    - ntp / syslog: jump via node_ip, private-only (public pool servers are not infra)
    - es_seed_hosts: jump via node_ip if the ES node was itself discovered (private)
    - swarmctl_storage nodes: stub CASTOR, no SSH needed
    """
    candidates: List[Candidate] = []
    seen: set = set()
    node_ip = result.get("server_ip", "")

    def _add(
        raw_ip: str,
        source: str,
        hint_role: str = "",
        jump_host_ip: str = "",
        private_only: bool = False,
    ) -> None:
        ip = raw_ip.split(":")[0].strip()
        if not ip or ip in known_ips or ip in seen:
            return
        if ip.startswith("127.") or ip in ("0.0.0.0", "::1"):
            return
        if private_only and not _is_private(ip):
            return  # discard public pool.ntp.org, public syslog endpoints etc.
        seen.add(ip)
        candidates.append(Candidate(
            ip=ip, source=source, hint_role=hint_role, jump_host_ip=jump_host_ip,
        ))

    # Direct-access sources (same public network as seeds)
    for ip in result.get("keepalived_peers", []):
        _add(ip, "keepalived_peer", "HAPROXY")
    for be in result.get("haproxy_backends", []):
        be_ip = be.get("ip", "") if isinstance(be, dict) else getattr(be, "ip", "")
        _add(be_ip, "haproxy_backend", "CONTENT_GATEWAY")

    # Private-network sources — tunnel through the node that exposed them
    for ip in result.get("gw_cluster_ips", []):
        _add(ip, "gw_cluster", "CASTOR", jump_host_ip=node_ip)
    for ip in result.get("gw_es_ips", []):
        _add(ip, "gw_es", "ELASTICSEARCH", jump_host_ip=node_ip)
    for ip in result.get("gw_lcs_ips", []):
        _add(ip, "gw_lcs", "LISTING_CACHE_SERVER", jump_host_ip=node_ip)

    # NTP and syslog: only private IPs are cluster-internal nodes
    for ip in result.get("ntp_client_servers", []):
        _add(ip, "ntp_target", "SCS", jump_host_ip=node_ip, private_only=True)
    for ip in result.get("syslog_targets", []):
        _add(ip, "syslog_target", "SCS", jump_host_ip=node_ip, private_only=True)

    # ES peers: jump if this ES node was itself discovered (implies private network)
    jump = node_ip if result.get("is_discovered") else ""
    for ip in result.get("es_seed_hosts", []):
        _add(ip, "es_seed", "ELASTICSEARCH", jump_host_ip=jump)

    # swarmctl-confirmed storage nodes → CASTOR stub (no SSH needed)
    for node in result.get("discovered_storage_nodes", []):
        node_entry_ip = node.get("ip", "") if isinstance(node, dict) else getattr(node, "ip", "")
        _add(node_entry_ip, "swarmctl_storage", "CASTOR")

    return candidates


# ─── Multi-wave discovery ─────────────────────────────────────────────────────

def _audit_node_wrapped(
    ip: str,
    port: int,
    creds: List[Credential],
    audit_sh: bytes,
    jump_ip: str = "",
    jump_creds: Optional[List[Credential]] = None,
    is_discovered: bool = False,
    discovered_source: str = "",
) -> dict:
    """
    Thin wrapper around _audit_node that stamps is_discovered / discovered_source
    and catches any unexpected exception to avoid crashing the thread pool.
    """
    try:
        result = _audit_node(ip, port, creds, audit_sh, jump_ip, jump_creds)
    except Exception as exc:
        log.error(_fail(f"{ip}: unhandled exception in _audit_node: {exc}"))
        result = _make_error_result(ip, ip, f"Unhandled: {exc}")

    result["is_discovered"] = is_discovered
    result["discovered_source"] = discovered_source
    return result


def _build_castor_stub(cand: Candidate) -> dict:
    """
    Build a CASTOR stub result for swarmctl-confirmed storage nodes.
    No SSH attempted — replicates the same stub as run_audit_with_discovery.
    """
    suffix = cand.ip.split(".")[-1]
    result = _make_error_result(cand.ip, f"castor-{suffix}", None)  # type: ignore[arg-type]
    result.update({
        "success": True,
        "error": None,
        "roles": [{"role": "CASTOR", "reason": "swarmctl-confirmed storage node"}],
        "is_discovered": True,
        "discovered_source": cand.source,
    })
    return result


def run_discovery(
    seeds: List[str],
    creds: List[Credential],
    max_waves: int = MAX_WAVES,
    default_port: int = 22,
) -> List[dict]:
    """
    Multi-wave SSH audit starting from seed IPs.

    Wave 0: audit all seeds in parallel.
    Wave 1..N: extract candidate IPs from previous wave, audit them in parallel.

    Returns a flat list of AuditResult-compatible dicts (all waves combined).
    """
    try:
        audit_sh = _get_audit_script()
    except RuntimeError as exc:
        log.error(_fail(f"Cannot load audit script: {exc}"))
        sys.exit(1)

    default_cred = next((c for c in creds if c.is_default), None)
    # Fallback credential list: default first, then others
    fallback_creds = (
        [default_cred] + [c for c in creds if not c.is_default]
        if default_cred else list(creds)
    )

    known_ips: set = set(seeds)
    all_results: List[dict] = []

    log.info(_info(f"Starting discovery — {len(seeds)} seed(s): {seeds}"))
    log.info(_info(f"Credentials: {[c.name for c in creds]} — default: {default_cred.name if default_cred else 'none'}"))

    # Wave 0 — audit seeds
    log.info(_info(f"=== Wave 0: auditing {len(seeds)} seed(s) ==="))
    wave_results: List[dict] = []

    try:
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(seeds) or 1)) as pool:
            futures = {
                pool.submit(
                    _audit_node_wrapped,
                    ip, default_port, fallback_creds, audit_sh,
                    is_discovered=False, discovered_source="seed",
                ): ip
                for ip in seeds
            }
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    log.error(_fail(f"{ip}: thread error in wave 0: {exc}"))
                    result = _make_error_result(ip, ip, f"Thread error: {exc}")
                wave_results.append(result)
                if result["success"]:
                    roles = [r["role"] if isinstance(r, dict) else r.get("role", "") for r in result.get("roles", [])]
                    log.info(_ok(f"  {ip} ({result.get('server_name', ip)}): roles={roles}"))
                else:
                    log.info(_fail(f"  {ip}: {result.get('error', 'unknown error')}"))
    except Exception as exc:
        log.error(_fail(f"Wave 0 thread pool crashed: {exc}"))

    all_results.extend(wave_results)

    if not default_cred:
        log.info(_skip("No default credential — skipping discovery waves"))
        return all_results

    # Waves 1..N
    for wave_num in range(1, max_waves + 1):
        candidates: List[Candidate] = []
        seen_this_wave: set = set()

        for result in wave_results:
            if not result.get("success"):
                continue
            try:
                new_cands = extract_candidates(result, known_ips)
            except Exception as exc:
                log.warning(f"extract_candidates failed for {result.get('server_ip', '?')}: {exc}")
                new_cands = []

            for cand in new_cands:
                if cand.ip not in seen_this_wave:
                    seen_this_wave.add(cand.ip)
                    known_ips.add(cand.ip)
                    candidates.append(cand)
                    jump_info = f" via jump {cand.jump_host_ip}" if cand.jump_host_ip else " direct"
                    log.info(_info(f"  candidate: {cand.ip} source={cand.source} role={cand.hint_role}{jump_info}"))

        if not candidates:
            log.info(_info(f"=== Wave {wave_num}: no candidates — stopping ==="))
            break

        log.info(_info(f"=== Wave {wave_num}: probing {len(candidates)} candidate(s) ==="))
        wave_results = []

        try:
            with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(candidates))) as pool:
                futures_map = {}
                for cand in candidates:
                    if cand.source == "swarmctl_storage":
                        # CASTOR stub — no SSH, submit a trivial callable
                        f = pool.submit(_build_castor_stub, cand)
                    else:
                        f = pool.submit(
                            _audit_node_wrapped,
                            cand.ip,
                            default_port,
                            fallback_creds,
                            audit_sh,
                            cand.jump_host_ip,
                            fallback_creds if cand.jump_host_ip else None,
                            True,
                            cand.source,
                        )
                    futures_map[f] = cand

                for future in as_completed(futures_map):
                    cand = futures_map[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        log.error(_fail(f"{cand.ip}: thread error in wave {wave_num}: {exc}"))
                        result = _make_error_result(cand.ip, cand.ip, f"Thread error: {exc}")
                        result["is_discovered"] = True
                        result["discovered_source"] = cand.source

                    wave_results.append(result)
                    if result["success"]:
                        roles = [r["role"] if isinstance(r, dict) else r.get("role", "") for r in result.get("roles", [])]
                        log.info(_ok(f"  {cand.ip}: roles={roles}"))
                    else:
                        log.info(_fail(f"  {cand.ip}: {result.get('error', 'unknown error')}"))

        except Exception as exc:
            log.error(_fail(f"Wave {wave_num} thread pool crashed: {exc}"))

        all_results.extend(wave_results)

    log.info(_info(f"Discovery complete — {len(all_results)} total node(s)"))
    return all_results


# ─── Archive generation ───────────────────────────────────────────────────────

def build_archive(
    results: List[dict],
    output_path: Path,
    metadata: dict,
) -> None:
    """
    Write a tar.gz archive importable by ARCIS /api/import/offline.

    Structure:
      manifest.json        — collection metadata (format, version, counts, etc.)
      audit_results.json   — flat list of all AuditResult dicts
      nodes/<ip>.json      — individual per-node result files
    """
    success_count = sum(1 for r in results if r.get("success"))

    # Infer cluster name from first ES result that has one
    cluster_name = ""
    for r in results:
        if r.get("es_cluster_name"):
            cluster_name = r["es_cluster_name"]
            break

    manifest = {
        "format": "arcis-offline-v1",
        "collector_version": VERSION,
        "collected_at": metadata.get("collected_at", datetime.now(timezone.utc).isoformat()),
        "node_count": len(results),
        "success_count": success_count,
        "seeds": metadata.get("seeds", []),
        "waves": metadata.get("waves", 0),
        "cluster_name": cluster_name,
    }

    try:
        with tarfile.open(output_path, "w:gz") as tar:

            def _add_json(name: str, obj: object) -> None:
                """Serialize obj to JSON and add it to the archive as name."""
                raw = json.dumps(obj, ensure_ascii=False, indent=2, default=str).encode("utf-8")
                info = tarfile.TarInfo(name=name)
                info.size = len(raw)
                tar.addfile(info, io.BytesIO(raw))

            _add_json("manifest.json", manifest)
            _add_json("audit_results.json", results)

            for result in results:
                ip = result.get("server_ip", "unknown").replace("/", "_")
                _add_json(f"nodes/{ip}.json", result)

        log.info(_ok(f"Archive written: {output_path} ({output_path.stat().st_size} bytes)"))

    except Exception as exc:
        log.error(_fail(f"Failed to write archive {output_path}: {exc}"))
        raise


# ─── Interactive prompts ──────────────────────────────────────────────────────

def prompt_yes_no(msg: str, default: bool = True) -> bool:
    """Prompt user for a yes/no answer. Returns default on empty input."""
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            answer = input(f"{msg} {hint}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  Please enter y or n.")


def prompt_seeds() -> List[str]:
    """
    Interactively collect seed IP addresses.
    Accepts comma-separated input or one IP per line (empty line to stop).
    """
    print("\n=== Seed IP Addresses ===")
    print("Enter seed IPs (comma-separated, or one per line; empty line to stop):")
    seeds: List[str] = []
    while True:
        try:
            line = input("  IP: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            if seeds:
                break
            print("  At least one seed IP is required.")
            continue
        for part in line.split(","):
            ip = part.strip()
            if ip:
                seeds.append(ip)
        if seeds and not line.endswith(","):
            # Stop after a non-comma-terminated line with at least one IP
            if "," not in line:
                break
    return seeds


def prompt_credentials() -> List[Credential]:
    """
    Interactively collect one or more SSH credential profiles.
    At least one profile is required.
    """
    print("\n=== SSH Credentials ===")
    creds: List[Credential] = []

    while True:
        print(f"\n--- Credential #{len(creds) + 1} ---")
        try:
            name = input("  Profile name (e.g. 'default'): ").strip() or f"cred-{len(creds)+1}"
            username = input("  SSH username: ").strip() or "root"
            auth_choice = input("  Auth method — (p)assword or (k)ey? [p]: ").strip().lower() or "p"

            if auth_choice.startswith("k"):
                key_path = input("  Path to private key [~/.ssh/id_rsa]: ").strip() or "~/.ssh/id_rsa"
                key_path = str(Path(key_path).expanduser())
                password = None
            else:
                password = getpass.getpass("  Password: ")
                key_path = None

            port_str = input("  SSH port [22]: ").strip() or "22"
            try:
                port = int(port_str)
            except ValueError:
                port = 22

            is_default = prompt_yes_no("  Mark as default credential?", default=(len(creds) == 0))

        except (EOFError, KeyboardInterrupt):
            print()
            break

        creds.append(Credential(
            name=name,
            username=username,
            password=password,
            private_key_path=key_path,
            port=port,
            is_default=is_default,
        ))
        print(f"  Added credential '{name}'.")

        if not prompt_yes_no("  Add another credential?", default=False):
            break

    if not creds:
        print("ERROR: no credentials provided — aborting.", file=sys.stderr)
        sys.exit(1)

    return creds


def prompt_options() -> dict:
    """Interactively collect collection options (max waves, output path)."""
    print("\n=== Collection Options ===")
    try:
        waves_str = input(f"  Max discovery waves [{MAX_WAVES}]: ").strip() or str(MAX_WAVES)
        try:
            max_waves = max(0, int(waves_str))
        except ValueError:
            max_waves = MAX_WAVES

        out_dir_str = input("  Output directory [.]: ").strip() or "."
        out_dir = Path(out_dir_str).expanduser()

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"arcis_offline_{ts}.tar.gz"
        out_name = input(f"  Output filename [{default_name}]: ").strip() or default_name

    except (EOFError, KeyboardInterrupt):
        print()
        max_waves = MAX_WAVES
        out_dir = Path(".")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_name = f"arcis_offline_{ts}.tar.gz"

    return {"max_waves": max_waves, "output_dir": out_dir, "output_filename": out_name}


# ─── Main ─────────────────────────────────────────────────────────────────────

def _print_banner() -> None:
    """Print startup banner to stderr."""
    print(file=sys.stderr)
    print(f"  ARCIS-SWARM Offline Collector v{VERSION}", file=sys.stderr)
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", file=sys.stderr)
    print(file=sys.stderr)


def _print_summary(results: List[dict], output_path: Path) -> None:
    """Print a human-readable summary of the collection run to stderr."""
    total = len(results)
    ok = sum(1 for r in results if r.get("success"))
    failed = total - ok
    seeds_found = sum(1 for r in results if not r.get("is_discovered"))
    discovered = sum(1 for r in results if r.get("is_discovered"))

    print(file=sys.stderr)
    print("  === Collection Summary ===", file=sys.stderr)
    print(f"  Total nodes  : {total}", file=sys.stderr)
    print(f"  Success      : {ok}", file=sys.stderr)
    print(f"  Failed       : {failed}", file=sys.stderr)
    print(f"  Seeds        : {seeds_found}", file=sys.stderr)
    print(f"  Discovered   : {discovered}", file=sys.stderr)
    print(f"  Archive      : {output_path}", file=sys.stderr)
    print(file=sys.stderr)
    if ok > 0:
        print("  Import into ARCIS:", file=sys.stderr)
        print(f"    curl -X POST http://<arcis-host>:8000/api/import/offline \\", file=sys.stderr)
        print(f"         -F file=@{output_path}", file=sys.stderr)
    print(file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ARCIS-SWARM Offline Collector — SSH multi-wave infrastructure discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--seeds", metavar="IPs",
        help="Comma-separated seed IP addresses (e.g. 10.0.0.1,10.0.0.2)"
    )
    parser.add_argument("--user", metavar="USER", help="SSH username")
    parser.add_argument("--password", metavar="PASS", help="SSH password")
    parser.add_argument("--key", metavar="PATH", help="Path to SSH private key")
    parser.add_argument("--port", metavar="PORT", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--max-waves", metavar="N", type=int, default=MAX_WAVES,
        help=f"Max discovery waves (default: {MAX_WAVES})"
    )
    parser.add_argument("--output-dir", metavar="DIR", default=".", help="Output directory")
    parser.add_argument(
        "--no-interactive", action="store_true",
        help="Disable interactive prompts (requires --seeds and --user + --password or --key)"
    )
    args = parser.parse_args()

    _print_banner()

    interactive = not args.no_interactive

    # ── Collect seeds ──────────────────────────────────────────────────────────
    if args.seeds:
        seeds = [ip.strip() for ip in args.seeds.split(",") if ip.strip()]
    elif interactive:
        seeds = prompt_seeds()
    else:
        log.error(_fail("--seeds is required in --no-interactive mode"))
        sys.exit(1)

    if not seeds:
        log.error(_fail("No seed IPs provided — aborting"))
        sys.exit(1)

    # ── Collect credentials ────────────────────────────────────────────────────
    if args.user and (args.password or args.key):
        cred = Credential(
            name="cli",
            username=args.user,
            password=args.password,
            private_key_path=str(Path(args.key).expanduser()) if args.key else None,
            port=args.port,
            is_default=True,
        )
        creds = [cred]
    elif interactive:
        creds = prompt_credentials()
    else:
        log.error(_fail("In --no-interactive mode, provide --user with --password or --key"))
        sys.exit(1)

    # ── Collect options ────────────────────────────────────────────────────────
    if interactive and not (args.seeds and (args.password or args.key)):
        opts = prompt_options()
        max_waves = opts["max_waves"]
        output_dir = opts["output_dir"]
        output_filename = opts["output_filename"]
    else:
        max_waves = args.max_waves
        output_dir = Path(args.output_dir).expanduser()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"arcis_offline_{ts}.tar.gz"

    output_dir = Path(output_dir)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        log.error(_fail(f"Cannot create output directory {output_dir}: {exc}"))
        sys.exit(1)

    output_path = output_dir / output_filename

    # ── Run discovery ──────────────────────────────────────────────────────────
    collected_at = datetime.now(timezone.utc).isoformat()
    try:
        results = run_discovery(seeds, creds, max_waves=max_waves, default_port=args.port)
    except KeyboardInterrupt:
        log.warning("Interrupted by user — saving partial results")
        results = []
    except Exception as exc:
        log.error(_fail(f"Discovery failed: {exc}"))
        sys.exit(1)

    if not results:
        log.error(_fail("No results collected — aborting"))
        sys.exit(1)

    # ── Build archive ──────────────────────────────────────────────────────────
    metadata = {
        "collected_at": collected_at,
        "seeds": seeds,
        "waves": max_waves,
    }
    try:
        build_archive(results, output_path, metadata)
    except Exception as exc:
        log.error(_fail(f"Archive generation failed: {exc}"))
        sys.exit(1)

    _print_summary(results, output_path)


if __name__ == "__main__":
    main()
