# Version: 2.4.0
# Date:    2026-06-20
# Notes:   Jump-host support for private-network targets (GW→Storage/ES/LCS via SSH tunnel)

from __future__ import annotations
import asyncio
import json
import logging
import uuid
from pathlib import Path
from typing import AsyncIterator, Optional

import asyncssh

from models import AuditResult, Credential, Server, DiscoveredServer, DiscoveryWave, DiscoveryRun

log = logging.getLogger(__name__)

SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "audit.sh"
SSH_CONNECT_TIMEOUT = 20   # seconds — TCP connect + SSH handshake + auth
SCRIPT_TIMEOUT     = 600   # seconds — script execution (GW/SCS can be slow)


async def _make_connect_kwargs(host: str, credential: Credential, tunnel=None) -> dict:
    """Build asyncssh.connect() kwargs for the given credential, optionally tunnelled."""
    kw: dict = {
        "host": host,
        "port": credential.port,
        "username": credential.username,
        "known_hosts": None,
        "connect_timeout": SSH_CONNECT_TIMEOUT,
    }
    if tunnel is not None:
        kw["tunnel"] = tunnel
    if credential.private_key:
        kw["client_keys"] = [asyncssh.import_private_key(credential.private_key)]
    elif credential.password:
        kw["password"] = credential.password
    else:
        raise ValueError("Credential has neither password nor private_key")
    return kw


async def audit_server(
    server: Server,
    credential: Credential,
    tunnel=None,  # open asyncssh.SSHClientConnection to use as SSH jump host
) -> AuditResult:
    base = AuditResult(
        server_id=server.id,
        server_name=server.name,
        server_ip=server.ip,
        success=False,
    )

    try:
        connect_kwargs = await _make_connect_kwargs(server.ip, credential, tunnel=tunnel)

        # Wrap the entire connect+auth in a hard timeout — asyncssh connect_timeout
        # only covers TCP; auth can still hang indefinitely on some setups.
        try:
            conn_ctx = await asyncio.wait_for(
                asyncssh.connect(**connect_kwargs),
                timeout=SSH_CONNECT_TIMEOUT,
            )
        except asyncio.TimeoutError:
            base.error = f"SSH connect timeout after {SSH_CONNECT_TIMEOUT}s"
            return base

        async with conn_ctx as conn:
            script_content = SCRIPT_PATH.read_bytes()
            # Unique name per session — avoids collision if the same host is audited concurrently
            remote_script = f"/tmp/_arcis_audit_{uuid.uuid4().hex[:8]}.sh"

            async with conn.start_sftp_client() as sftp:
                async with sftp.open(remote_script, "wb") as f:
                    await f.write(script_content)
            log.info("TMP WRITE  %s:%s (%d bytes)", server.ip, remote_script, len(script_content))

            await conn.run(f"chmod +x {remote_script}", check=True)

            try:
                result = await asyncio.wait_for(
                    conn.run(f"bash {remote_script}", check=False),
                    timeout=SCRIPT_TIMEOUT,
                )
            finally:
                await conn.run(f"rm -f {remote_script}", check=False)
                log.info("TMP DELETE %s:%s", server.ip, remote_script)

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
        base.error = f"Script timeout after {SCRIPT_TIMEOUT}s"
    except asyncssh.Error as e:
        base.error = f"SSH error: {e}"
    except Exception as e:
        log.exception("Unexpected error auditing %s", server.ip)
        base.error = str(e)

    return base


_NO_RETRY_ERRORS = ("Script timeout", "Script exit", "JSON parse")


def _should_retry(err: str) -> bool:
    """True if the error is an auth/SSH failure worth retrying with another cred."""
    if not err:
        return False
    if any(kw in err for kw in _NO_RETRY_ERRORS):
        return False   # script executed — wrong cred won't help
    if "connect timeout" in err:
        return False   # host unreachable — no point trying other creds
    return True        # SSH/auth error → try next cred


async def _open_jump(jump_host_ip: str, creds: list[Credential]):
    """Open an SSH connection to the jump host (try all creds). Returns conn or None."""
    for cred in creds:
        try:
            kw = await _make_connect_kwargs(jump_host_ip, cred)
            conn = await asyncio.wait_for(asyncssh.connect(**kw), timeout=SSH_CONNECT_TIMEOUT)
            log.info("Jump host %s: connected via cred '%s'", jump_host_ip, cred.name)
            return conn
        except asyncio.TimeoutError:
            log.info("Jump host %s: connect timeout with cred '%s'", jump_host_ip, cred.name)
            return None   # unreachable — stop trying
        except asyncssh.Error as e:
            log.info("Jump host %s: SSH error with cred '%s': %s", jump_host_ip, cred.name, e)
        except Exception as e:
            log.info("Jump host %s: error with cred '%s': %s", jump_host_ip, cred.name, e)
    return None


async def audit_server_with_fallback(
    server: Server,
    ordered_creds: list[Credential],
    jump_host_ip: str = "",
    jump_host_creds: Optional[list[Credential]] = None,
) -> AuditResult:
    """
    Try credentials in order (default first), optionally via a jump host.
    - jump_host_ip: if set, open that bastion first and tunnel through it.
    - jump_host_creds: credentials to try on the jump host (same list as ordered_creds by default).
    Retries only on SSH/auth errors, never on connect timeout or script errors.
    """
    tunnel = None
    tunnel_owner = None  # the conn we opened and must close

    try:
        if jump_host_ip:
            jcreds = jump_host_creds or ordered_creds
            tunnel_owner = await _open_jump(jump_host_ip, jcreds)
            if tunnel_owner is None:
                return AuditResult(
                    server_id=server.id, server_name=server.name, server_ip=server.ip,
                    success=False,
                    error=f"Jump host {jump_host_ip} unreachable (tried {len(jcreds)} cred(s))",
                )
            tunnel = tunnel_owner

        last: Optional[AuditResult] = None
        for cred in ordered_creds:
            log.debug("Trying cred '%s' on %s (jump=%s)", cred.name, server.ip, jump_host_ip or "none")
            r = await audit_server(server, cred, tunnel=tunnel)
            if r.success:
                return r
            last = r
            if not _should_retry(r.error or ""):
                return r
            log.info("Cred '%s' failed on %s (%s) — trying next", cred.name, server.ip, (r.error or "")[:60])

        return last or AuditResult(
            server_id=server.id, server_name=server.name, server_ip=server.ip,
            success=False, error="No credential available",
        )
    finally:
        if tunnel_owner is not None:
            tunnel_owner.close()


async def run_audit(
    servers: list[Server],
    credentials: list[Credential],
    on_result=None,
) -> list[AuditResult]:
    """
    Audit all servers concurrently.  For each server: try the assigned credential
    first (if set), then default, then all others.  Fastest-first via gather.
    """
    cred_map   = {c.id: c for c in credentials}
    default_cred = next((c for c in credentials if c.is_default), None)

    def _ordered_creds(srv: Server) -> list[Credential]:
        """Build fallback list: assigned → default → rest, deduped, no None."""
        seen_ids: set[str] = set()
        result: list[Credential] = []
        for c in [
            cred_map.get(srv.credential_id or ""),
            default_cred,
            *[c for c in credentials if not c.is_default],
        ]:
            if c and c.id not in seen_ids:
                seen_ids.add(c.id)
                result.append(c)
        return result

    async def _task(srv: Server) -> AuditResult:
        creds = _ordered_creds(srv)
        if not creds:
            r = AuditResult(
                server_id=srv.id, server_name=srv.name, server_ip=srv.ip,
                success=False, error="No credential available",
            )
        else:
            r = await audit_server_with_fallback(srv, creds)
        if on_result:
            on_result(r)
        return r

    return list(await asyncio.gather(*[_task(s) for s in servers]))


async def run_audit_with_discovery(
    seed_servers: list[Server],
    credentials: list[Credential],
    on_result=None,
    max_waves: int = 4,
) -> list[AuditResult]:
    """
    Multi-wave audit: audit seeds first, then SSH into each IP discovered from
    their configs (keepalived peers, HAProxy backends, gateway cluster/ES/LCS IPs,
    NTP targets, syslog targets).  Repeats until no new IPs or max_waves reached.
    Discovered nodes get is_discovered=True and discovered_source set.
    For each discovered node, tries default credential first, then all others on failure.
    """
    default_cred = next((c for c in credentials if c.is_default), None)
    known_ips: set[str] = {s.ip for s in seed_servers}
    all_results: list[AuditResult] = []

    # Wave 0 — audit configured seed servers
    wave_results = await run_audit(seed_servers, credentials, on_result=on_result)
    all_results.extend(wave_results)

    if not default_cred:
        log.info("No default credential — skipping discovery waves")
        return all_results

    # Ordered fallback list: default first, then all others
    fallback_creds = [default_cred] + [c for c in credentials if not c.is_default]

    for wave in range(1, max_waves + 1):
        candidates: list[DiscoveredServer] = []
        seen: set[str] = set()
        for r in wave_results:
            if not r.success:
                continue
            for cand in extract_candidate_ips(r, known_ips):
                if cand.ip not in seen:
                    seen.add(cand.ip)
                    known_ips.add(cand.ip)
                    candidates.append(cand)

        if not candidates:
            # Log what fields each wave result had, to help diagnose empty discovery
            for r in wave_results:
                if r.success:
                    log.info(
                        "Discovery wave %d — %s (%s): keepalived=%d ha_backends=%d "
                        "gw_cluster=%d gw_es=%d gw_lcs=%d ntp=%d syslog=%d es_seed=%d",
                        wave, r.server_ip, r.server_name,
                        len(r.keepalived_peers), len(r.haproxy_backends),
                        len(r.gw_cluster_ips), len(r.gw_es_ips), len(r.gw_lcs_ips),
                        len(r.ntp_client_servers), len(r.syslog_targets), len(r.es_seed_hosts),
                    )
            log.info("Discovery wave %d: no new candidates — stopping", wave)
            break

        log.info("Discovery wave %d: %d new IPs to probe — %s", wave, len(candidates),
                 [c.ip for c in candidates])
        source_map = {c.ip: c for c in candidates}

        async def _disc_task(cand: DiscoveredServer) -> AuditResult:
            suffix = cand.ip.split(".")[-1]
            role_prefix = cand.hint_role.lower().replace("_", "-") or "node"
            srv = Server(name=f"{role_prefix}-{suffix}", ip=cand.ip, credential_id=None)
            if cand.jump_host_ip:
                log.info("Probing %s via jump host %s", cand.ip, cand.jump_host_ip)
            r = await audit_server_with_fallback(
                srv, fallback_creds,
                jump_host_ip=cand.jump_host_ip,
                jump_host_creds=fallback_creds,
            )
            r.is_discovered = True
            r.discovered_source = source_map[cand.ip].source
            if on_result:
                on_result(r)
            return r

        wave_results = list(await asyncio.gather(*[_disc_task(c) for c in candidates]))
        all_results.extend(wave_results)

    return all_results


def extract_candidate_ips(
    result: AuditResult,
    known_ips: set[str],
) -> list[DiscoveredServer]:
    """
    Extract candidate IPs to discover from an audit result.
    Sources that expose private-network IPs (gw_cluster, gw_es, gw_lcs) carry
    jump_host_ip = result.server_ip so the discovery wave tunnels through the GW.
    """
    candidates: list[DiscoveredServer] = []
    seen: set[str] = set()

    def _add(raw_ip: str, source: str, hint_role: str = "", jump_host_ip: str = "") -> None:
        ip = raw_ip.split(":")[0].strip()
        if not ip or ip in known_ips or ip in seen:
            return
        if ip.startswith("127.") or ip == "0.0.0.0" or ip == "::1":
            return
        seen.add(ip)
        candidates.append(DiscoveredServer(
            ip=ip, source=source, hint_role=hint_role, jump_host_ip=jump_host_ip,
        ))

    # Same-network sources — no jump needed
    for ip in result.keepalived_peers:
        _add(ip, "keepalived_peer", "HAPROXY")
    for be in result.haproxy_backends:
        _add(be.ip, "haproxy_backend", "CONTENT_GATEWAY")
    for ip in result.ntp_client_servers:
        _add(ip, "ntp_target", "SCS")
    for ip in result.syslog_targets:
        _add(ip, "syslog_target", "SCS")

    # Private-network sources — tunnel through the GW that reported them
    gw_ip = result.server_ip  # the GW is the jump host for its private targets
    for ip in result.gw_cluster_ips:
        _add(ip, "gw_cluster", "CASTOR", jump_host_ip=gw_ip)
    for ip in result.gw_es_ips:
        _add(ip, "gw_es", "ELASTICSEARCH", jump_host_ip=gw_ip)
    for ip in result.gw_lcs_ips:
        _add(ip, "gw_lcs", "LISTING_CACHE_SERVER", jump_host_ip=gw_ip)

    # ES peers: same subnet as the reporting ES node — use it as jump if it was itself jumped
    jump = result.server_ip if result.is_discovered else ""
    for ip in result.es_seed_hosts:
        _add(ip, "es_seed", "ELASTICSEARCH", jump_host_ip=jump)

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
