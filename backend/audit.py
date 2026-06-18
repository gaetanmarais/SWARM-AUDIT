# Version: 1.5.0
# Date:    2026-06-18
# Notes:   Map logs field (last-24h per-role application logs) from audit JSON

from __future__ import annotations
import asyncio
import json
import logging
from pathlib import Path
from typing import AsyncIterator, Optional

import asyncssh

from models import AuditResult, Credential, Server

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
