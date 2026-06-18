# Version: 1.8.0
# Date:    2026-06-18
# Notes:   Add is_syslog_server / is_ntp_server / is_dhcp_server / is_pxe_server to AuditResult

from __future__ import annotations
from typing import Optional, Literal
from pydantic import BaseModel, Field
import uuid


# ─── Credential profiles ──────────────────────────────────────────────────────

class CredentialCreate(BaseModel):
    name: str
    username: str
    password: Optional[str] = None
    private_key: Optional[str] = None
    port: int = 22
    is_default: bool = False


class Credential(CredentialCreate):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))


# ─── Server inventory ─────────────────────────────────────────────────────────

class ServerCreate(BaseModel):
    name: str
    ip: str
    credential_id: Optional[str] = None


class Server(ServerCreate):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))


# ─── Audit result sub-types ───────────────────────────────────────────────────

class RoleDetection(BaseModel):
    role: str
    reason: str


class CpuInfo(BaseModel):
    count: int
    model: str


class RamInfo(BaseModel):
    total_mb: int
    free_mb: int


class DiskInfo(BaseModel):
    device: str
    size_gb: int
    avail_gb: int
    used_pct: str
    mount: str


class NetConnection(BaseModel):
    proto: str
    state: str
    local_port: str
    remote_addr: str
    remote_port: str
    process: str


class ListenPort(BaseModel):
    port: str
    process: str


class NetworkInterface(BaseModel):
    iface: str
    ip: str
    prefix: str


class InstalledPackage(BaseModel):
    name: str
    version: str
    release: str = ""
    arch: str = ""


class HaproxyBackend(BaseModel):
    name: str
    ip: str
    port: str


class DiscoveredStorageNode(BaseModel):
    ip: str
    status: str = ""
    uptime: str = ""
    avail_pct: str = ""
    used: str = ""
    max: str = ""
    streams: str = ""
    version: str = ""
    errors: str = ""
    health_report: Optional[dict] = None  # raw per-node SNMP JSON from swarmctl -Q healthreport


class DiscoveredEsNode(BaseModel):
    ip: str
    name: str


# ─── Audit result ─────────────────────────────────────────────────────────────

class AuditResult(BaseModel):
    server_id: str
    server_name: str
    server_ip: str
    success: bool
    error: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    kernel: Optional[str] = None
    uptime_sec: Optional[int] = None
    cpu: Optional[CpuInfo] = None
    ram: Optional[RamInfo] = None
    disks: list[DiskInfo] = []
    roles: list[RoleDetection] = []
    # Network topology
    network_interfaces: list[NetworkInterface] = []
    config_files: list[str] = []
    config_contents: dict[str, str] = {}  # path → stripped content (no comments)
    installed_packages: list[InstalledPackage] = []
    haproxy_backends: list[HaproxyBackend] = []
    haproxy_vips: list[str] = []            # VIPs from keepalived virtual_ipaddress
    # Gateway config-based topology
    gw_config_path: str = ""
    gw_cluster_ips: list[str] = []    # Swarm cluster entry IPs
    gw_es_ips: list[str] = []         # ES node IPs
    gw_lcs_ips: list[str] = []        # LCS/Redis node IPs
    # Dynamically discovered nodes
    swarm_cluster_summary: str = ""
    discovered_storage_nodes: list[DiscoveredStorageNode] = []
    es_cluster_name: str = ""
    discovered_es_nodes: list[DiscoveredEsNode] = []
    es_seed_hosts: list[str] = []
    es_cat_health: str = ""     # _cat/health?v output
    es_cat_indices: str = ""    # _cat/indices?v output
    # Swarm cluster health report (raw JSON from swarmctl -Q healthreport)
    health_report_json: Optional[dict] = None
    # Elasticsearch enriched data
    es_cat_nodes: str = ""        # _cat/nodes?v with resource metrics
    es_node_stats: str = ""       # _nodes/stats/indices/search,indexing (JSON)
    es_cat_alloc: str = ""        # _cat/allocation?v
    es_disk_info: Optional[dict] = None  # ES data disk type + latency
    # Infrastructure service roles (set by audit script on the node that runs the service)
    is_syslog_server: bool = False
    is_ntp_server: bool = False
    is_dhcp_server: bool = False
    is_pxe_server: bool = False
    # Live data
    listen_ports: list[ListenPort] = []
    connections: list[NetConnection] = []


# ─── Audit run ────────────────────────────────────────────────────────────────

class AuditRun(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str
    finished_at: Optional[str] = None
    status: Literal["running", "done", "error"] = "running"
    results: list[AuditResult] = []


# ─── Inventory file ───────────────────────────────────────────────────────────

class Inventory(BaseModel):
    credentials: list[Credential] = []
    servers: list[Server] = []
    last_audit: Optional[AuditRun] = None
