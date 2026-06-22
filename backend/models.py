# Version: 2.7.0
# Date:    2026-06-22
# Notes:   DiscoveredStorageNode — extract chassis_id from SNMP healthreport

from __future__ import annotations
from typing import Optional, Literal
from pydantic import BaseModel, Field, model_validator
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
    chassis_id: str = ""

    @model_validator(mode="after")
    def _extract_chassis_id(self) -> "DiscoveredStorageNode":
        if not self.chassis_id and self.health_report:
            self.chassis_id = (
                self.health_report.get("SNMP objects", {}).get("Chassis Id", "") or ""
            )
        return self


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
    # Infrastructure service flags — set regardless of primary role; shown as tile badges
    is_syslog_server: bool = False
    is_ntp_server: bool = False
    is_dhcp_server: bool = False
    is_pxe_server: bool = False
    is_rabbitmq: bool = False
    is_prometheus: bool = False
    is_alertmanager: bool = False
    is_grafana: bool = False
    is_s3: bool = False
    is_content_ui: bool = False
    is_storage_ui: bool = False
    # Discovery: where this node points for time sync and log forwarding
    ntp_client_servers: list[str] = []   # NTP server IPs configured on this node
    syslog_targets: list[str] = []       # Remote syslog forwarding targets
    keepalived_peers: list[str] = []     # VRRP unicast peers (other HA nodes)
    # Set by run_audit_with_discovery() on nodes found beyond the seed list
    is_discovered: bool = False
    discovered_source: str = ""  # keepalived_peer|haproxy_backend|gw_cluster|gw_es|gw_lcs|ntp_target|syslog_target|es_seed
    # Live data
    listen_ports: list[ListenPort] = []
    connections: list[NetConnection] = []
    # Application logs — last 24h, deduplicated, keyed by role name
    logs: dict[str, str] = {}
    # Feed replication data from swarmctl -Q feeds (raw text, may be None if unavailable)
    swarmctl_feeds: Optional[str] = None


# ─── Auto-discovery ───────────────────────────────────────────────────────────

class DiscoveredServer(BaseModel):
    ip: str
    source: str   # keepalived_peer|haproxy_backend|gw_cluster|gw_es|gw_lcs|ntp_target|syslog_target|es_seed
    hint_role: str = ""   # guessed role from discovery source
    jump_host_ip: str = ""  # if non-empty: SSH via this bastion to reach ip (private-network targets)


class DiscoveryWave(BaseModel):
    wave: int
    candidates: list[DiscoveredServer] = []
    reached: int = 0    # successfully SSH-audited
    new_added: int = 0  # unique IPs added to results this wave


class DiscoveryRun(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str
    finished_at: Optional[str] = None
    status: Literal["idle", "running", "done", "error"] = "running"
    waves: list[DiscoveryWave] = []
    total_discovered: int = 0
    error: Optional[str] = None


# ─── Audit run ────────────────────────────────────────────────────────────────

class AuditRun(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str
    finished_at: Optional[str] = None
    status: Literal["running", "done", "error"] = "running"
    results: list[AuditResult] = []


# ─── Analysis results ─────────────────────────────────────────────────────────

class AnalysisFinding(BaseModel):
    severity: Literal["CRITICAL", "WARNING", "INFO", "OK"] = "INFO"
    title: str = ""
    detail: str = ""
    current_value: str = ""      # exact misconfigured line(s) from the config file
    corrected_config: str = ""   # ready-to-paste corrected config snippet
    recommendation: str = ""
    doc_reference: str = ""      # DataCore/Swarm doc title or URL if available in RAG
    servers: list[str] = []


class AnalysisModule(BaseModel):
    role: str
    servers: list[str] = []
    summary: str = ""
    config_findings: list[AnalysisFinding] = []
    log_findings: list[AnalysisFinding] = []
    analyzed_configs: list[str] = []   # config file paths included in the analysis prompt
    analyzed_logs: list[str] = []      # log source keys included in the analysis prompt


class AnalysisResult(BaseModel):
    status: Literal["idle", "running", "done", "error", "cancelled"] = "idle"
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error: Optional[str] = None
    progress: str = ""  # live status message during "running" state
    modules: list[AnalysisModule] = []
    cross_correlations: list[AnalysisFinding] = []


# ─── Inventory settings ────────────────────────────────────────────────────────

class InventorySettings(BaseModel):
    mcp_hub_url: str = "https://claude-ws-gmarais.duckdns.org/mcp"
    mcp_hub_token: str = ""
    anthropic_api_key: str = ""
    # "auto" = prefer direct if api_key set; "hub_mcp" = always Hub MCP ask_claude; "direct" = always Anthropic API
    analysis_backend: Literal["auto", "hub_mcp", "direct"] = "auto"


# ─── Inventory file ───────────────────────────────────────────────────────────

class Inventory(BaseModel):
    credentials: list[Credential] = []
    servers: list[Server] = []
    last_audit: Optional[AuditRun] = None
    last_analysis: Optional[AnalysisResult] = None
    last_discovery: Optional[DiscoveryRun] = None
    settings: InventorySettings = Field(default_factory=InventorySettings)
