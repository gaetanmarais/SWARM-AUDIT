# Version: 2.0.0
# Date:    2026-06-20
# Notes:   Add extract_candidate_ips(), run_discovery(); map ntp/syslog/keepalived fields

from __future__ import annotations
import asyncio
import json
import logging
from pathlib import Path
from typing import AsyncIterator, Optional

import asyncssh

from models import AuditResult, Credential, Server, DiscoveredServer, DiscoveryWave, DiscoveryRun

log = logging.getLogger(__name__)

SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "audit.sh"
REMOTE_SCRIPT = "/tmp/_arcis_audit.sh"
TIMEOUT = 600  # seconds per host — GW/SCS collect healthreport per storage node (≈47s×N max)


async def audit_server(
    server: Server,
    credential: Credential,
) -> AuditResult:
    base = AuditResult(
        server_id=server.id,
        server_name=server.name,
        server_ip=server.ip,
        success=False,
    )

    try:
        connect_kwargs: dict = {
            "host": server.ip,
            "port": credential.port,
            "username": credential.username,
            "known_hosts": None,
            "connect_timeout": 15,
        }
        if credential.private_key:
            connect_kwargs["client_keys"] = [
                asyncssh.import_private_key(credential.private_key)
            ]
        elif credential.password:
            connect_kwargs["password"] = credential.password
        else:
            raise ValueError("Credential has neither password nor private_key")

        async with asyncssh.connect(**connect_kwargs) as conn:
            script_content = SCRIPT_PATH.read_bytes()

            async with conn.start_sftp_client() as sftp:
                async with sftp.open(REMOTE_SCRIPT, "wb") as f:
                    await f.write(script_content)
            await conn.run(f"chmod +x {REMOTE_SCRIPT}", check=True)

            result = await asyncio.wait_for(
                conn.run(f"bash {REMOTE_SCRIPT}", check=False),
                timeout=TIMEOUT,
            )
            await conn.run(f"rm -f {REMOTE_SCRIPT}", check=False)

            if result.returncode != 0:
                base.error = f"Script exit {result.returncode}: {result.stderr[:500]}"
                return base

            raw = result.stdout.strip()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as e:
                # Log enough context to find the offending character
                char = e.pos or 0
                snippet = raw[max(0, char - 40): char + 40]
                log.error(
                    "JSON parse error on %s at char %d: %s | near: %r",
                    server.ip, char, e, snippet,
                )
                base.error = f"JSON parse error: {e}"
                return base

            return AuditResult(
                server_id=server.id,
                server_name=server.name,
                server_ip=server.ip,
                success=True,
                hostname=data.get("hostname"),
                os=data.get("os"),
                kernel=data.get("kernel"),
                uptime_sec=data.get("uptime_sec"),
                cpu=data.get("cpu"),
                ram=data.get("ram"),
                disks=data.get("disks", []),
                roles=data.get("roles", []),
                network_interfaces=data.get("network_interfaces", []),
                config_files=data.get("config_files", []),
                config_contents=data.get("config_contents", {}),
                installed_packages=data.get("installed_packages", []),
                haproxy_vips=data.get("haproxy_vips", []),
                haproxy_backends=data.get("haproxy_backends", []),
                gw_config_path=data.get("gw_config_path", ""),
                gw_cluster_ips=data.get("gw_cluster_ips", []),
                gw_es_ips=data.get("gw_es_ips", []),
                gw_lcs_ips=data.get("gw_lcs_ips", []),
                swarm_cluster_summary=data.get("swarm_cluster_summary", ""),
                discovered_storage_nodes=data.get("discovered_storage_nodes", []),
                es_cluster_name=data.get("es_cluster_name", ""),
                discovered_es_nodes=data.get("discovered_es_nodes", []),
                es_seed_hosts=data.get("es_seed_hosts", []),
                es_cat_health=data.get("es_cat_health", ""),
                es_cat_indices=data.get("es_cat_indices", ""),
                listen_ports=data.get("listen_ports", []),
                connections=data.get("connections", []),
                health_report_json=data.get("health_report_json"),
                es_cat_nodes=data.get("es_cat_nodes", ""),
                es_node_stats=data.get("es_node_stats", ""),
                es_cat_alloc=data.get("es_cat_alloc", ""),
                es_disk_info=data.get("es_disk_info"),
                is_syslog_server=data.get("is_syslog_server", False),
                is_ntp_server=data.get("is_ntp_server", False),
                is_dhcp_server=data.get("is_dhcp_server", False),
                is_pxe_server=data.get("is_pxe_server", False),
                ntp_client_servers=data.get("ntp_client_servers", []),
                syslog_targets=data.get("syslog_targets", []),
                keepalived_peers=data.get("keepalived_peers", []),
                logs=data.get("logs", {}),
            )

    except asyncio.TimeoutError:
        base.error = f"Timeout after {TIMEOUT}s"
    except asyncssh.Error as e:
        base.error = f"SSH error: {e}"
    except Exception as e:
        log.exception("Unexpected error auditing %s", server.ip)
        base.error = str(e)

    return base


async def run_audit(
    servers: list[Server],
    credentials: list[Credential],
    on_result=None,
) -> list[AuditResult]:
    """
    Audit all servers concurrently.  Results are appended to the shared list as
    each SSH session completes (fastest-first).  on_result(result) is called
    after each node so callers can update live state.
    """
    cred_map = {c.id: c for c in credentials}
    default_cred = next((c for c in credentials if c.is_default), None)

    async def _task(srv: Server) -> AuditResult:
        cred = cred_map.get(srv.credential_id or "") or default_cred
        if not cred:
            r = AuditResult(
                server_id=srv.id, server_name=srv.name, server_ip=srv.ip,
                success=False, error="No credential available",
            )
        else:
            r = await audit_server(srv, cred)
        if on_result:
            on_result(r)
        return r

    return list(await asyncio.gather(*[_task(s) for s in servers]))


def extract_candidate_ips(
    result: AuditResult,
    known_ips: set[str],
) -> list[DiscoveredServer]:
    """Extract candidate IPs to discover from an audit result."""
    candidates: list[DiscoveredServer] = []
    seen: set[str] = set()

    def _add(raw_ip: str, source: str, hint_role: str = "") -> None:
        ip = raw_ip.split(":")[0].strip()
        if not ip or ip in known_ips or ip in seen:
            return
        seen.add(ip)
        candidates.append(DiscoveredServer(ip=ip, source=source, hint_role=hint_role))

    for ip in result.keepalived_peers:
        _add(ip, "keepalived_peer", "HAPROXY")
    for be in result.haproxy_backends:
        _add(be.ip, "haproxy_backend", "CONTENT_GATEWAY")
    for ip in result.gw_cluster_ips:
        _add(ip, "gw_cluster", "CASTOR")
    for ip in result.gw_es_ips:
        _add(ip, "gw_es", "ELASTICSEARCH")
    for ip in result.gw_lcs_ips:
        _add(ip, "gw_lcs", "LISTING_CACHE_SERVER")
    for ip in result.es_seed_hosts:
        _add(ip, "es_seed", "ELASTICSEARCH")
    for ip in result.ntp_client_servers:
        _add(ip, "ntp_target", "SCS")
    for ip in result.syslog_targets:
        _add(ip, "syslog_target", "SCS")
    return candidates


async def run_discovery(
    seed_servers: list[Server],
    credentials: list[Credential],
    on_wave_done=None,
    max_waves: int = 5,
) -> DiscoveryRun:
    """
    Multi-wave SSH discovery starting from seed_servers.
    Each wave audits new IPs found from previous wave results.
    Uses the default credential for all discovered nodes.
    """
    from datetime import datetime, timezone
    run = DiscoveryRun(started_at=datetime.now(timezone.utc).isoformat())

    cred_map = {c.id: c for c in credentials}
    default_cred = next((c for c in credentials if c.is_default), None)

    # known_ips: all IPs we've already audited or attempted
    known_ips: set[str] = {s.ip for s in seed_servers}
    all_results: list[AuditResult] = []

    # Wave 0: audit seeds
    wave0 = DiscoveryWave(wave=0, candidates=[
        DiscoveredServer(ip=s.ip, source="seed", hint_role="") for s in seed_servers
    ])
    seed_results = await run_audit(seed_servers, credentials)
    wave0.reached = sum(1 for r in seed_results if r.success)
    wave0.new_added = len(seed_results)
    all_results.extend(seed_results)
    run.waves.append(wave0)
    if on_wave_done:
        on_wave_done(wave0, seed_results)

    for wave_num in range(1, max_waves + 1):
        # Collect all candidate IPs from this wave's results
        candidates: list[DiscoveredServer] = []
        seen_this_wave: set[str] = set()
        for r in (seed_results if wave_num == 1 else prev_results):
            for cand in extract_candidate_ips(r, known_ips):
                if cand.ip not in seen_this_wave:
                    seen_this_wave.add(cand.ip)
                    candidates.append(cand)

        if not candidates:
            break

        # Build synthetic Server objects for each candidate
        new_servers: list[Server] = []
        for cand in candidates:
            known_ips.add(cand.ip)
            # Name: hint_role prefix + IP suffix
            suffix = cand.ip.split(".")[-1]
            role_prefix = cand.hint_role.lower().replace("_", "-") or "node"
            new_servers.append(Server(
                name=f"{role_prefix}-{suffix}",
                ip=cand.ip,
                credential_id=None,  # will use default
            ))

        if not default_cred:
            log.warning("No default credential — stopping discovery at wave %d", wave_num)
            break

        wave = DiscoveryWave(wave=wave_num, candidates=candidates)
        prev_results = await run_audit(new_servers, credentials)
        wave.reached = sum(1 for r in prev_results if r.success)
        wave.new_added = len(new_servers)
        all_results.extend(prev_results)
        run.waves.append(wave)
        if on_wave_done:
            on_wave_done(wave, prev_results)

    run.total_discovered = len(all_results) - len(seed_servers)
    return run
