#!/usr/bin/env bash
# Version: 2.18.0
# Date:    2026-06-20
# Notes:   Add NTP/syslog client collection, keepalived unicast peers; fix _has_role early-call bug.

set -euo pipefail

# ─── Helpers ─────────────────────────────────────────────────────────────────

proc_running()   { pgrep -x "$1" &>/dev/null; }
proc_running_f() { pgrep -f "$1" &>/dev/null; }
svc_active()     { systemctl is-active --quiet "$1" 2>/dev/null; }
port_listening()     { ss -tlnp 2>/dev/null | grep -q ":${1} "; }
udp_port_listening() { ss -ulnp 2>/dev/null | grep -q ":${1} "; }
file_exists()    { [ -f "$1" ] || [ -d "$1" ]; }
bin_exists()     { command -v "$1" &>/dev/null || [ -x "$1" ]; }

# pkg_installed PATTERN — checks dpkg or rpm for an installed package matching
# an extended-regex pattern (case-insensitive).
pkg_installed() {
    local pat="$1"
    if command -v dpkg &>/dev/null; then
        dpkg -l 2>/dev/null | awk '/^ii/{print $2}' | grep -qiE "$pat"
    elif command -v rpm &>/dev/null; then
        rpm -qa 2>/dev/null | grep -qiE "$pat"
    else
        return 1
    fi
}

# Pure-bash JSON string escaping — no sed, works on bash 3.1+
jq_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# ─── System specs ─────────────────────────────────────────────────────────────

CPU_COUNT=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 0)
CPU_MODEL=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo "unknown")
RAM_TOTAL_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
RAM_FREE_MB=$(awk '/MemAvailable/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)

DISK_JSON="[]"
if command -v df &>/dev/null; then
    _raw_disk=$(df -BG 2>/dev/null | tail -n +2 \
        | grep -v "^tmpfs\|^udev\|^overlay\|^devtmpfs" \
        | awk '{
            dev=$1; mount=$NF
            sz=$2; gsub(/G/,"",sz)
            av=$4; gsub(/G/,"",av)
            pct=$5
            printf "{\"device\":\"%s\",\"size_gb\":%s,\"avail_gb\":%s,\"used_pct\":\"%s\",\"mount\":\"%s\"},",
                   dev, sz, av, pct, mount
          }' 2>/dev/null \
        | sed 's/,$//' || true)
    [ -n "$_raw_disk" ] && DISK_JSON="[${_raw_disk}]"
fi

HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
OS_PRETTY=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || uname -s)
KERNEL=$(uname -r)
UPTIME_SEC=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)

# ─── Network interfaces (all IPs, public + private) ───────────────────────────

NETWORK_INTERFACES="[]"
_ni_raw=$(ip addr show 2>/dev/null | awk '
    /^[0-9]+:/ {
        iface=$2; gsub(/:$/,"",iface)
    }
    /inet / {
        split($2,a,"/"); ip=a[1]; prefix=a[2]
        if (ip !~ /^127\./ && ip !~ /^::1$/)
            printf "{\"iface\":\"%s\",\"ip\":\"%s\",\"prefix\":\"%s\"},", iface, ip, prefix
    }' 2>/dev/null \
    | sed 's/,$//' || true)
[ -n "$_ni_raw" ] && NETWORK_INTERFACES="[${_ni_raw}]"

# ─── Network connections ──────────────────────────────────────────────────────

NET_CONNS="[]"
_raw_conns=$(ss -tupn 2>/dev/null | tail -n +2 \
  | awk '
    {
      proto=$1; state=$2
      split($5, la, ":"); lport=la[length(la)]
      split($6, ra, ":"); rport=ra[length(ra)]
      raddr=""
      for(i=1;i<length(ra);i++) raddr=raddr (i>1?":":"") ra[i]
      proc=""
      if (match($0, /users:\(\("[^"]+"/)) {
          proc=substr($0, RSTART+9, RLENGTH-10)
          # Escape backslashes and quotes in proc name
          gsub(/\\/,"\\\\",proc)
          gsub(/"/,"\\\"",proc)
      }
      # Skip IPv6 addresses (contain ":") and unroutable destinations
      if (raddr != "" && raddr != "*" && raddr != "0.0.0.0" \
          && raddr != "[::]" && raddr != "127.0.0.1" \
          && raddr !~ /:/)
        printf "{\"proto\":\"%s\",\"state\":\"%s\",\"local_port\":\"%s\",\"remote_addr\":\"%s\",\"remote_port\":\"%s\",\"process\":\"%s\"},",
          proto, state, lport, raddr, rport, proc
    }' 2>/dev/null \
  | sed 's/,$//' || true)
[ -n "$_raw_conns" ] && NET_CONNS="[${_raw_conns}]"

# ─── Role detection ───────────────────────────────────────────────────────────

ROLES="[]"
add_role() {
    local role="$1"
    local reason="${2//\"/\\\"}"
    local entry="{\"role\":\"${role}\",\"reason\":\"${reason}\"}"
    if [ "$ROLES" = "[]" ]; then
        ROLES="[${entry}]"
    else
        ROLES="${ROLES%]},${entry}]"
    fi
}
_has_role() { printf '%s' "$ROLES" | grep -q "\"role\":\"$1\""; }

# ─── HAPROXY ────────────────────────────────────────────────────────────────
# Require process/service RUNNING — config file alone is not enough (haproxy
# is a common dep that may sit on GW nodes without being active).
if proc_running haproxy || svc_active haproxy; then
    add_role "HAPROXY" "process/svc:haproxy running"
fi

# ─── CONTENT GATEWAY (DataCore CloudScaler / CloudGateway) ──────────────────
# Package caringo-gateway is authoritative; service or cfg must also confirm it
# is the active gateway role (not a co-installed bystander like on HAPROXY).
_gw_pkg=false
_gw_svc=false
pkg_installed "^caringo-gateway" && _gw_pkg=true
if proc_running "cloudgateway" || svc_active "cloudgateway" \
   || svc_active "caringo-gateway"; then
    _gw_svc=true
fi

# ─── LISTING CACHE SERVER — detect BEFORE content gateway ───────────────────
# LCS nodes run rabbitmq alongside caringo-gateway. Any rabbitmq indicator
# (port, process, service, package) is sufficient — no AND required.
_is_lcs=false
_rabbitmq_any=false
proc_running_f "rabbitmq"    && _rabbitmq_any=true
proc_running "beam.smp"      && _rabbitmq_any=true  # Erlang VM (rabbitmq runtime)
svc_active "rabbitmq-server" && _rabbitmq_any=true
svc_active "rabbitmq"        && _rabbitmq_any=true
pkg_installed "rabbitmq"     && _rabbitmq_any=true
port_listening 5672          && _rabbitmq_any=true  # AMQP
port_listening 15672         && _rabbitmq_any=true  # management UI

if $_rabbitmq_any \
   || svc_active "listingcache" \
   || pkg_installed "caringo-listingcache" \
   || file_exists /opt/caringo/listingcache/conf/listingcache.cfg; then
    add_role "LISTING_CACHE_SERVER" "rabbitmq/listingcache detected"
    _is_lcs=true
fi

# CONTENT_GATEWAY: skip if this node is primarily an LCS node
if ! $_is_lcs; then
    if $_gw_svc \
       || ( $_gw_pkg && ( file_exists /etc/caringo/cloudgateway/gateway.cfg \
                       || file_exists /etc/caringo/cloudgateway/cloudgateway.cfg ) ); then
        add_role "CONTENT_GATEWAY" "pkg:caringo-gateway + (svc running or gateway.cfg)"
    fi
fi

# ─── CONTENT UI (caringo-gateway-webui) ─────────────────────────────────────
# Served from a Content Gateway host; detected by its own package/service/cfg.
if pkg_installed "^caringo-gateway-webui" \
   || svc_active "contentportal" || svc_active "content-portal" \
   || file_exists /opt/caringo/contentportal/conf/contentportal.cfg \
   || file_exists /etc/caringo/contentportal/contentportal.cfg; then
    add_role "CONTENT_UI" "pkg:caringo-gateway-webui or svc:contentportal"
fi

# ─── STORAGE UI (caringo-storage-webui) ─────────────────────────────────────
# Require SERVICE RUNNING or CONFIG FILE — package alone is not enough.
# caringo-storage-webui is installed on HAProxy nodes as a dependency without
# the storageui daemon being active, which produces false positives.
if svc_active "storageui" \
   || file_exists /opt/caringo/storageui/conf/storageui.cfg; then
    add_role "STORAGE_UI" "svc:storageui active or cfg present"
fi

# ─── SCS / CSN (Swarm Cluster Services / Platform Server) ───────────────────
# Key indicator: /usr/sbin/scsctl binary (only on SCS nodes).
if file_exists /usr/sbin/scsctl \
   || bin_exists scsctl \
   || svc_active "caringo-csn" || svc_active "csn" || svc_active "scs" \
   || proc_running "csn" \
   || pkg_installed "caringo-csn|caringo-scs|swarm-scs" \
   || file_exists /etc/caringo/csn/conf.d/csn.cfg \
   || file_exists /var/opt/caringo/netboot/content/cluster.cfg; then
    add_role "SCS" "binary/svc/pkg/cfg: scsctl|csn|scs"
fi

# CSN Platform Server (older branding — legacy installs)
if svc_active "csn" || file_exists /opt/caringo/csn/conf/csn.cfg; then
    add_role "CSN_PLATFORM" "svc:csn or legacy csn.cfg"
fi

# ─── LISTING CACHE (Redis / Memcached) ───────────────────────────────────────
if proc_running "redis-server" || svc_active "redis" || svc_active "redis-server" \
   || port_listening 6379; then
    add_role "LISTING_CACHE" "process/port:redis:6379"
fi
if proc_running "memcached" || svc_active "memcached" || port_listening 11211; then
    add_role "LISTING_CACHE" "process/port:memcached:11211"
fi

# ─── ELASTICSEARCH ───────────────────────────────────────────────────────────
# caringo-elasticsearch-search is the DataCore-packaged Elasticsearch.
# Fallback: standard elasticsearch service or API confirmation.
# NEVER use port 9200 alone — Swarm storage nodes also expose 9200 for metrics.
_es_detected=false
if pkg_installed "^caringo-elasticsearch-search" \
   || svc_active "elasticsearch" \
   || file_exists /etc/elasticsearch/elasticsearch.yml; then
    _es_detected=true
elif port_listening 9200 && command -v curl &>/dev/null; then
    if curl -sf --connect-timeout 3 "http://127.0.0.1:9200" 2>/dev/null \
       | grep -q '"cluster_name"'; then
        _es_detected=true
    fi
fi
$_es_detected && add_role "ELASTICSEARCH" "pkg/svc:elasticsearch or API on :9200"

# ─── FOUNDATION DB ───────────────────────────────────────────────────────────
if proc_running "fdbserver" || svc_active "foundationdb" \
   || file_exists /etc/foundationdb/fdb.cluster; then
    add_role "FOUNDATION_DB" "process/svc:fdbserver or fdb.cluster"
fi

# ─── SWARM FS / NFS gateway ──────────────────────────────────────────────────
if proc_running "swarmfs" || svc_active "swarmfs" \
   || file_exists /opt/caringo/swarmfs/conf/swarmfs.cfg; then
    add_role "SWARMFS" "process/svc:swarmfs or cfg"
fi

# ─── CASTOR (DataCore Swarm storage node) ────────────────────────────────────
# node.cfg is the definitive Castor fingerprint — present only on storage nodes.
# Exclude HAProxy/Gateway nodes that may have caringo packages installed as deps.
if ! _has_role "HAPROXY" && ! _has_role "CONTENT_GATEWAY"; then
    if proc_running "castor" || svc_active "castor" || svc_active "castord" \
       || svc_active "datacore-castor" \
       || file_exists /etc/caringo/node.cfg \
       || file_exists /var/opt/caringo/node; then
        add_role "CASTOR" "process/svc/cfg:castor storage node"
    fi
fi

# ─── TELEMETRY (Prometheus / Grafana) ───────────────────────────────────────
_telemetry_reason=""
if proc_running "prometheus" || svc_active "prometheus" \
   || file_exists /etc/prometheus/prometheus.yml \
   || port_listening 9090; then
    _telemetry_reason="prometheus"
fi
if proc_running "grafana" || proc_running "grafana-server" \
   || svc_active "grafana" || svc_active "grafana-server" \
   || port_listening 3000; then
    _telemetry_reason="${_telemetry_reason:+${_telemetry_reason}+}grafana"
fi
if proc_running "alertmanager" || svc_active "alertmanager" \
   || file_exists /etc/alertmanager/alertmanager.yml \
   || port_listening 9093; then
    _telemetry_reason="${_telemetry_reason:+${_telemetry_reason}+}alertmanager"
fi
[ -n "$_telemetry_reason" ] && add_role "TELEMETRY" "process/svc:${_telemetry_reason}"

# ─── UNKNOWN fallback ────────────────────────────────────────────────────────
if [ "$ROLES" = "[]" ]; then
    add_role "UNKNOWN" "no known Swarm component fingerprint detected"
fi

# ─── Infrastructure service detection ────────────────────────────────────────
# Flags set regardless of main role — shown as feature badges on the diagram tile.
IS_SYSLOG_SERVER=false
IS_NTP_SERVER=false
IS_DHCP_SERVER=false
IS_PXE_SERVER=false
IS_RABBITMQ=false
IS_PROMETHEUS=false
IS_ALERTMANAGER=false
IS_GRAFANA=false
IS_CONTENT_UI=false
IS_STORAGE_UI=false

if proc_running rsyslogd || proc_running syslogd || proc_running_f "syslog-ng" \
   || svc_active rsyslog || svc_active "syslog-ng" \
   || udp_port_listening 514; then
    IS_SYSLOG_SERVER=true
fi

if proc_running ntpd || svc_active ntpd || svc_active ntp; then
    IS_NTP_SERVER=true
fi
# chronyd is both client and server; treat as server if it binds UDP 123
# or has an explicit 'allow' directive in its config.
if proc_running chronyd || svc_active chronyd; then
    if udp_port_listening 123 \
       || grep -qiE '^\s*allow\b' /etc/chrony.conf 2>/dev/null; then
        IS_NTP_SERVER=true
    fi
fi

if proc_running dhcpd || svc_active dhcpd || svc_active "isc-dhcp-server" \
   || svc_active "kea-dhcp4" || udp_port_listening 67; then
    IS_DHCP_SERVER=true
fi

if proc_running tftpd || proc_running "in.tftpd" || proc_running atftpd \
   || svc_active tftp || svc_active tftpd || svc_active atftpd \
   || file_exists /var/opt/caringo/netboot \
   || file_exists /var/lib/tftpboot \
   || udp_port_listening 69; then
    IS_PXE_SERVER=true
fi

# RabbitMQ broker (AMQP)
if proc_running_f "rabbitmq" || proc_running "beam.smp" \
   || svc_active "rabbitmq-server" || svc_active "rabbitmq" \
   || port_listening 5672 || port_listening 15672; then
    IS_RABBITMQ=true
fi

# Prometheus
if proc_running "prometheus" || svc_active "prometheus" \
   || file_exists /etc/prometheus/prometheus.yml \
   || port_listening 9090; then
    IS_PROMETHEUS=true
fi

# Alertmanager
if proc_running "alertmanager" || svc_active "alertmanager" \
   || port_listening 9093; then
    IS_ALERTMANAGER=true
fi

# Grafana
if proc_running "grafana-server" || proc_running "grafana" \
   || svc_active "grafana-server" || svc_active "grafana" \
   || file_exists /etc/grafana/grafana.ini \
   || port_listening 3000; then
    IS_GRAFANA=true
fi

# Content UI (caringo content portal)
if svc_active "contentportal" || svc_active "content-portal" \
   || file_exists /opt/caringo/contentportal/conf/contentportal.cfg \
   || file_exists /etc/caringo/contentportal/contentportal.cfg \
   || pkg_installed "^caringo-gateway-webui"; then
    IS_CONTENT_UI=true
fi

# Storage UI (caringo storage management UI)
if svc_active "storageui" || svc_active "swarm-ui" || svc_active "storage-ui" \
   || file_exists /opt/caringo/storageui/conf/storageui.cfg \
   || port_listening 91; then
    IS_STORAGE_UI=true
fi

# ─── NTP client servers (IPs this node synchronizes from) ─────────────────────
NTP_CLIENT_SERVERS="[]"
_ntp_ips=""
for _ntpf in /etc/chrony.conf /etc/chrony/chrony.conf /etc/ntp.conf /etc/ntpd.conf; do
    [ -f "$_ntpf" ] || continue
    _ntp_ips=$(grep -iE '^\s*(server|pool)\s+([0-9]{1,3}\.){3}[0-9]{1,3}' "$_ntpf" 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | sort -u | awk '{printf "\"%s\",", $1}' | sed 's/,$//' || true)
    [ -n "$_ntp_ips" ] && break
done
if [ -z "$_ntp_ips" ] && command -v chronyc &>/dev/null; then
    _ntp_ips=$(chronyc sources -n 2>/dev/null \
        | awk '/^\^[*+?]/{print $2}' \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | sort -u | awk '{printf "\"%s\",", $1}' | sed 's/,$//' || true)
fi
[ -n "$_ntp_ips" ] && NTP_CLIENT_SERVERS="[${_ntp_ips}]"

# ─── Syslog forwarding targets (remote syslog servers this node sends to) ────
SYSLOG_TARGETS="[]"
_syslog_ips=""
if [ -d /etc/rsyslog.d ] || [ -f /etc/rsyslog.conf ]; then
    _syslog_ips=$(cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null \
        | grep -v '^\s*#' \
        | grep -iE '@{1,2}([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | sort -u | awk '{printf "\"%s\",", $1}' | sed 's/,$//' || true)
fi
if [ -z "$_syslog_ips" ]; then
    for _sgf in /etc/syslog-ng/syslog-ng.conf /etc/syslog-ng/conf.d/*.conf; do
        [ -f "$_sgf" ] || continue
        _r=$(grep -hiE '(tcp|udp)\s*\(' "$_sgf" 2>/dev/null \
            | grep -oE '"([0-9]{1,3}\.){3}[0-9]{1,3}"' \
            | tr -d '"' | sort -u \
            | awk '{printf "\"%s\",", $1}' | sed 's/,$//' || true)
        [ -n "$_r" ] && { _syslog_ips="$_r"; break; }
    done
fi
[ -n "$_syslog_ips" ] && SYSLOG_TARGETS="[${_syslog_ips}]"

# ─── Listening ports snapshot ──────────────────────────────────────────────────

LISTEN_PORTS="[]"
_raw_ports=$(ss -tlnp 2>/dev/null | tail -n +2 \
  | awk '{
      split($4, a, ":"); port=a[length(a)]
      proc=""
      if (match($0, /users:\(\("[^"]+"/)) {
          proc=substr($0, RSTART+9, RLENGTH-10)
      }
      printf "{\"port\":\"%s\",\"process\":\"%s\"},", port, proc
    }' 2>/dev/null \
  | sed 's/,$//' || true)
[ -n "$_raw_ports" ] && LISTEN_PORTS="[${_raw_ports}]"

# ─── HAProxy VIPs (keepalived virtual_ipaddress blocks) ──────────────────────

HAPROXY_VIPS="[]"
if (proc_running haproxy || svc_active haproxy) \
   && [ -f /etc/keepalived/keepalived.conf ]; then
    _vips=$(awk '/virtual_ipaddress[[:space:]]*\{/,/\}/' \
            /etc/keepalived/keepalived.conf 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?' \
        | awk '{printf "\"%s\",", $1}' \
        | sed 's/,$//' || true)
    [ -n "$_vips" ] && HAPROXY_VIPS="[${_vips}]"
fi

# ─── Keepalived unicast peers (other HA nodes in the VRRP peer group) ─────────
KEEPALIVED_PEERS="[]"
_ka_peers_raw=""
_ka_conf_p=""
for _kf in /etc/keepalived/keepalived.conf /etc/keepalived.conf; do
    [ -f "$_kf" ] && { _ka_conf_p="$_kf"; break; }
done
if [ -z "$_ka_conf_p" ] && [ -d /etc/keepalived ]; then
    for _kf in /etc/keepalived/*.conf /etc/keepalived/conf.d/*.conf; do
        [ -f "$_kf" ] && { _ka_conf_p="$_kf"; break; }
    done
fi
if [ -n "$_ka_conf_p" ]; then
    _ka_peers_raw=$(awk '/unicast_peer[[:space:]]*\{/,/\}/' "$_ka_conf_p" 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | sort -u | awk '{printf "\"%s\",", $1}' | sed 's/,$//' || true)
    [ -z "$_ka_peers_raw" ] && _ka_peers_raw=$(grep -iE 'unicast_peer' "$_ka_conf_p" 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | sort -u | awk '{printf "\"%s\",", $1}' | sed 's/,$//' || true)
fi
[ -n "$_ka_peers_raw" ] && KEEPALIVED_PEERS="[${_ka_peers_raw}]"

# ─── HAProxy backends (config-based topology) ─────────────────────────────────

HAPROXY_BACKENDS="[]"
if [ -f /etc/haproxy/haproxy.cfg ]; then
    _be=$(grep -E "^\s+server\s+" /etc/haproxy/haproxy.cfg 2>/dev/null \
        | awk '{
            n=$2; a=$3
            split(a,p,":"); ip=p[1]; pt=(p[2]?p[2]:"")
            printf "{\"name\":\"%s\",\"ip\":\"%s\",\"port\":\"%s\"},", n, ip, pt
          }' \
        | sed 's/,$//' || true)
    [ -n "$_be" ] && HAPROXY_BACKENDS="[${_be}]"
fi

# ─── Config files present on this node ────────────────────────────────────────

CONFIG_FILES="[]"
CONFIG_CONTENTS="{}"   # {"path": "content..."} — stripped of comment lines

_cfg_paths=()
# HAProxy configs — only if haproxy is actually running
if proc_running haproxy || svc_active haproxy; then
    _cfg_paths+=(/etc/haproxy/haproxy.cfg)
    # keepalived: try standard path first, then scan directory for any .conf file
    if [ -f /etc/keepalived/keepalived.conf ]; then
        _cfg_paths+=(/etc/keepalived/keepalived.conf)
    elif [ -f /etc/keepalived.conf ]; then
        _cfg_paths+=(/etc/keepalived.conf)
    elif [ -d /etc/keepalived ]; then
        # Collect all .conf files in the directory (glob in array)
        for _kf in /etc/keepalived/*.conf; do
            [ -f "$_kf" ] && _cfg_paths+=("$_kf")
        done
        for _kf in /etc/keepalived/conf.d/*.conf; do
            [ -f "$_kf" ] && _cfg_paths+=("$_kf")
        done
    fi
fi
_cfg_paths+=(
    /etc/caringo/cloudgateway/gateway.cfg
    /etc/caringo/cloudgateway/cloudgateway.cfg
    /etc/caringo/csn/conf.d/csn.cfg
    /var/opt/caringo/netboot/content/cluster.cfg
    /etc/caringo/scspproxy/scspproxy.cfg
    /etc/caringo/scspproxy/hosts.cfg
    /opt/caringo/storageui/conf/storageui.cfg
    /opt/caringo/contentportal/conf/contentportal.cfg
    /opt/caringo/listingcache/conf/listingcache.cfg
    /opt/caringo/swarmfs/conf/swarmfs.cfg
    /etc/caringo/node.cfg
    /etc/caringo/cluster.cfg
    /opt/caringo/castor/conf/castor.cfg
    /var/opt/caringo/node/node.cfg
    /etc/foundationdb/fdb.cluster
    /etc/elasticsearch/elasticsearch.yml
    /etc/prometheus/prometheus.yml
    /etc/alertmanager/alertmanager.yml
    /etc/prometheus/alertmanager.yml
    /etc/alertmanager/alertmanager.yaml
    /opt/alertmanager/alertmanager.yml
    /etc/grafana/grafana.ini
    /etc/rabbitmq/rabbitmq.conf
    /etc/rabbitmq/rabbitmq.config
    /etc/rabbitmq/advanced.config
    /etc/chrony.conf
    /etc/chrony/chrony.conf
    /etc/ntp.conf
    /etc/dhcp/dhcpd.conf
    /etc/dhcpd.conf
    /etc/dhcp/dhcpd6.conf
    /etc/rsyslog.conf
    /etc/syslog-ng/syslog-ng.conf
    /etc/default/tftpd-hpa
    /etc/xinetd.d/tftp
)
# Prometheus alert/recording rules — glob-collected (may be multiple files)
for _rf in \
    /etc/prometheus/rules/*.yml      /etc/prometheus/rules/*.yaml \
    /etc/prometheus/rules.d/*.yml    /etc/prometheus/rules.d/*.yaml \
    /etc/prometheus/alerts/*.yml     /etc/prometheus/alerts/*.yaml \
    /etc/prometheus/conf.d/*.yml     /etc/prometheus/conf.d/*.yaml; do
    [ -f "$_rf" ] && _cfg_paths+=("$_rf")
done
# rsyslog drop-in configs
for _rf in /etc/rsyslog.d/*.conf; do
    [ -f "$_rf" ] && _cfg_paths+=("$_rf")
done
# syslog-ng drop-in configs
for _rf in /etc/syslog-ng/conf.d/*.conf; do
    [ -f "$_rf" ] && _cfg_paths+=("$_rf")
done

_cf=""
_cc_pairs=""
for _cfp in "${_cfg_paths[@]}"; do
    [ -f "$_cfp" ] || continue
    # Add to file list
    [ -n "$_cf" ] && _cf="${_cf},"
    _cf="${_cf}\"${_cfp}\""
    # Read content: strip comments/blanks, escape for JSON, truncate to 8KB
    _content=$(grep -vE '^\s*(#|;|//)' "$_cfp" 2>/dev/null \
        | grep -v '^\s*$' \
        | head -c 8192 \
        | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r//g' \
        | awk '{printf "%s\\n", $0}' \
        || true)
    [ -n "$_cc_pairs" ] && _cc_pairs="${_cc_pairs},"
    _cc_pairs="${_cc_pairs}\"$(jq_escape "$_cfp")\":\"${_content}\""
done
[ -n "$_cf" ] && CONFIG_FILES="[${_cf}]"
[ -n "$_cc_pairs" ] && CONFIG_CONTENTS="{${_cc_pairs}}"

# ─── SCS: collect config via scsctl (no static config files on SCS nodes) ────
# scsctl storage config show -d → cluster-wide storage parameters (from etcd)
# scsctl platform config show -d → platform/SCS service parameters (from etcd)
if _has_role "SCS" && command -v scsctl &>/dev/null 2>&1; then
    _scsctl_storage=$(scsctl storage config show -d 2>/dev/null | head -c 16384 || true)
    _scsctl_platform=$(scsctl platform config show -d 2>/dev/null | head -c 16384 || true)

    _inject_scsctl() {
        local _label="$1" _content="$2"
        [ -z "$_content" ] && return
        local _esc
        _esc=$(printf '%s' "$_content" \
            | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r//g' \
            | awk '{printf "%s\\n", $0}')
        [ -n "$_cc_pairs" ] && _cc_pairs="${_cc_pairs},"
        _cc_pairs="${_cc_pairs}\"${_label}\":\"${_esc}\""
        # also add to file list so analysis knows it exists
        [ -n "$_cf" ] && _cf="${_cf},"
        _cf="${_cf}\"${_label}\""
    }

    _inject_scsctl "scsctl://storage/config"  "$_scsctl_storage"
    _inject_scsctl "scsctl://platform/config" "$_scsctl_platform"

    # Rebuild JSON with the new entries
    [ -n "$_cf" ]       && CONFIG_FILES="[${_cf}]"
    [ -n "$_cc_pairs" ] && CONFIG_CONTENTS="{${_cc_pairs}}"
fi

# ─── Gateway config parsing ────────────────────────────────────────────────────
# Parse gateway.cfg to extract IPs for the Swarm cluster, ES, and LCS.
# The file is INI-style; sections determine what each IP refers to.

GW_CONFIG_PATH=""
GW_CLUSTER_IPS="[]"    # [scsp] / [cluster] → entry point to storage nodes
GW_ES_IPS="[]"         # [search] / [elasticsearch] → ES nodes
GW_LCS_IPS="[]"        # [listingcache] / [cache] → Redis/LCS nodes

for _f in \
    /etc/caringo/cloudgateway/gateway.cfg \
    /etc/caringo/cloudgateway/cloudgateway.cfg \
    /opt/caringo/cloudgateway/conf/gateway.cfg \
    /etc/datacore/gateway/gateway.cfg \
    /etc/datacore/cloudgateway/gateway.cfg \
    /opt/datacore/cloudgateway/gateway.cfg \
    /opt/datacore/cloudgateway/conf/gateway.cfg \
    /etc/swarm/gateway/gateway.cfg \
    /etc/swarm/cloudgateway/gateway.cfg; do
    [ -f "$_f" ] && { GW_CONFIG_PATH="$_f"; break; }
done
# Fallback: search common prefixes for any gateway.cfg
if [ -z "$GW_CONFIG_PATH" ]; then
    GW_CONFIG_PATH=$(find /etc /opt -maxdepth 6 -name "gateway.cfg" 2>/dev/null | head -1 || true)
fi

if [ -n "$GW_CONFIG_PATH" ]; then
    echo "[arcis] GW config: $GW_CONFIG_PATH" >&2
    _cur_sec=""
    _gw_cluster=""; _gw_es=""; _gw_lcs=""

    _gw_add() {
        local _ep="$1" _target="$2"
        local _raw="${_ep%%:*}"
        echo "$_raw" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return
        echo "$_raw" | grep -qE '^(127\.|0\.|255\.)' && return
        case "$_target" in
            cluster) [ -n "$_gw_cluster" ] && _gw_cluster="${_gw_cluster},"; _gw_cluster="${_gw_cluster}\"${_ep}\"" ;;
            es)      [ -n "$_gw_es" ]      && _gw_es="${_gw_es},";           _gw_es="${_gw_es}\"${_ep}\""           ;;
            lcs)     [ -n "$_gw_lcs" ]     && _gw_lcs="${_gw_lcs},";         _gw_lcs="${_gw_lcs}\"${_ep}\""         ;;
        esac
    }

    while IFS= read -r _line; do
        _line="${_line%%#*}"   # strip inline comments
        # Section header → track current section
        if echo "$_line" | grep -qE '^\s*\['; then
            _cur_sec=$(echo "$_line" | grep -oE '\[[a-zA-Z0-9_]+\]' | head -1 \
                | tr -d '[]' | tr '[:upper:]' '[:lower:]')
            continue
        fi
        # Must contain at least one IP address
        echo "$_line" | grep -qE '([0-9]{1,3}\.){3}[0-9]{1,3}' || continue

        # Known sections: extract ALL IPs regardless of key name
        case "$_cur_sec" in
            scsp|cluster|storage|proxy|castor|swarm|swarmproxy|storageproxy|storagecluster)
                while IFS= read -r _ep; do _gw_add "$_ep" cluster; done \
                    < <(echo "$_line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?' || true)
                ;;
            search|elasticsearch|elastic|indexer|es|fulltext|full_text|searchengine)
                while IFS= read -r _ep; do _gw_add "$_ep" es; done \
                    < <(echo "$_line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?' || true)
                ;;
            listingcache|listing_cache|cache|cacheserver|cache_server|redis|lcs|listing)
                while IFS= read -r _ep; do _gw_add "$_ep" lcs; done \
                    < <(echo "$_line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?' || true)
                ;;
            *)
                # Unknown section: use key/value keywords to classify
                _target=""
                if echo "$_line" | grep -qiE 'elasticsearch|es[._]host|search|elastic'; then
                    _target=es
                elif echo "$_line" | grep -qiE 'redis|listingcache|listing.cache|lcs|cache'; then
                    _target=lcs
                elif echo "$_line" | grep -qiE 'hosts?|nodes?|address|servers?|endpoint|entry|backend'; then
                    _target=cluster
                fi
                [ -n "$_target" ] && while IFS= read -r _ep; do _gw_add "$_ep" "$_target"; done \
                    < <(echo "$_line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?' || true)
                ;;
        esac
    done < "$GW_CONFIG_PATH"

    [ -n "$_gw_cluster" ] && GW_CLUSTER_IPS="[${_gw_cluster}]"
    [ -n "$_gw_es" ]      && GW_ES_IPS="[${_gw_es}]"
    [ -n "$_gw_lcs" ]     && GW_LCS_IPS="[${_gw_lcs}]"
    echo "[arcis] GW parse done — cluster=${GW_CLUSTER_IPS} es=${GW_ES_IPS} lcs=${GW_LCS_IPS}" >&2
fi

# ─── Discovery: Storage nodes via swarmctl ─────────────────────────────────────
# swarmctl may not be in PATH — check common install locations.

DISCOVERED_STORAGE_NODES="[]"
SWARM_CLUSTER_SUMMARY=""

# Locate swarmctl binary.
# Common paths: /root/dist, /home/<user>/dist, package installs, opt.
_swarmctl=""
for _sc in swarmctl /root/dist/swarmctl /usr/local/bin/swarmctl \
           /usr/bin/swarmctl /opt/caringo/bin/swarmctl /opt/swarmctl; do
    if command -v "$_sc" &>/dev/null 2>&1 || [ -x "$_sc" ]; then
        _swarmctl="$_sc"; break
    fi
done
# Glob-search home directories (/home/*/dist/swarmctl, /home/*/bin/swarmctl)
if [ -z "$_swarmctl" ]; then
    for _sc in /home/*/dist/swarmctl /home/*/bin/swarmctl /home/*/swarmctl; do
        [ -x "$_sc" ] && { _swarmctl="$_sc"; break; }
    done
fi

# Use first IP from gateway config
_cl_ip=$(echo "$GW_CLUSTER_IPS" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)

# Fallback: scan all config files for any 'hosts =' line and grab first private IP
if [ -z "$_cl_ip" ] && [ -n "$GW_CONFIG_PATH" ]; then
    _cl_ip=$(grep -iE '^\s*hosts\s*=' "$GW_CONFIG_PATH" 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | grep -vE '^(127\.|0\.|255\.)' | head -1 || true)
fi

# SCS fallback: use scsctl storage instance list to find a live storage node
# scsctl output format: "IP Address: <ip>" lines (one per registered instance)
if [ -z "$_cl_ip" ] && [ -n "$_swarmctl" ] && command -v scsctl &>/dev/null 2>&1; then
    _scs_ips=$(scsctl storage instance list 2>/dev/null | awk '/IP Address:/{print $3}' || true)
    for _sip in $_scs_ips; do
        _test=$(timeout 3 "$_swarmctl" -d "$_sip" 2>/dev/null | head -5 || true)
        if echo "$_test" | grep -q '|'; then
            _cl_ip="$_sip"
            break
        fi
    done
fi

if [ -n "$_cl_ip" ] && [ -n "$_swarmctl" ]; then
    # swarmctl -d <ip> (no extra flag) lists ALL nodes with status/capacity/version
    # Output format: | Node | IP | status | upTime | avail% | usedSpace | maxSpace | streamCount | swVer | errCount | volErrs |
    _sw_raw=$("$_swarmctl" -d "$_cl_ip" 2>/dev/null || true)

    if [ -n "$_sw_raw" ]; then
        # ── Step 1: collect node list ──────────────────────────────────────────
        # Build an associative-style list: _node_<ip>_* variables
        _node_ips=""
        while IFS= read -r _row; do
            echo "$_row" | grep -qE '^\|\s*Node\s*\|' || continue
            _f_name=$(   echo "$_row" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$3); print $3}')
            echo "$_f_name" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || continue
            _f_status=$( echo "$_row" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$4); print $4}')
            _f_uptime=$( echo "$_row" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$5); print $5}')
            _f_avail=$(  echo "$_row" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$6); print $6}')
            _f_used=$(   echo "$_row" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$7); print $7}')
            _f_max=$(    echo "$_row" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$8); print $8}')
            _f_streams=$(echo "$_row" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$9); print $9}')
            _f_ver=$(    echo "$_row" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$10); print $10}')
            _f_errs=$(   echo "$_row" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$11); print $11}')
            # Store per-node fields in temp vars (safe key: dots replaced by _)
            _key="${_f_name//./_}"
            eval "_nd_${_key}_status='${_f_status}'"
            eval "_nd_${_key}_uptime='${_f_uptime}'"
            eval "_nd_${_key}_avail='${_f_avail}'"
            eval "_nd_${_key}_used='${_f_used}'"
            eval "_nd_${_key}_max='${_f_max}'"
            eval "_nd_${_key}_streams='${_f_streams}'"
            eval "_nd_${_key}_ver='${_f_ver}'"
            eval "_nd_${_key}_errs='${_f_errs}'"
            _node_ips="${_node_ips} ${_f_name}"
        done <<< "$_sw_raw"

        # Cluster summary
        _summary=$(echo "$_sw_raw" | grep -i "Logical Objects:" | xargs || true)
        [ -n "$_summary" ] && SWARM_CLUSTER_SUMMARY="$_summary"

        # ── Step 2: healthreport per node ─────────────────────────────────────
        # swarmctl -d <ip> -Q healthreport returns full SNMP JSON per node.
        # swarmctl may emit status/header lines before the JSON — strip them.

        # ── Step 3: build JSON array ───────────────────────────────────────────
        _sn=""
        for _ip in $_node_ips; do
            _key="${_ip//./_}"
            eval "_st=\${_nd_${_key}_status:-}"
            eval "_ut=\${_nd_${_key}_uptime:-}"
            eval "_av=\${_nd_${_key}_avail:-}"
            eval "_us=\${_nd_${_key}_used:-}"
            eval "_mx=\${_nd_${_key}_max:-}"
            eval "_sr=\${_nd_${_key}_streams:-}"
            eval "_vr=\${_nd_${_key}_ver:-}"
            eval "_er=\${_nd_${_key}_errs:-}"

            # Fetch per-node healthreport.
            # swarmctl may check isatty() and suppress stdout when piped — try:
            #   1. -x /tmp/file export (cleanest, if flag is supported)
            #   2. script -q fake-TTY capture (handles isatty checks)
            # ANSI codes are stripped before JSON parsing.
            _hr_file="/tmp/_swhr_${_ip//./_}"
            _hr_json="null"
            rm -f "$_hr_file"

            # Attempt 1: -x export flag — let swarmctl write its own output file.
            # Give it 15s: if swarmctl exits quickly (bad flag or no data), we fail
            # fast and move on; if it works, the file will be populated.
            timeout 15 "$_swarmctl" -d "$_ip" -Q healthreport -x "$_hr_file" 2>/dev/null || true

            # Attempt 2: script fake-TTY — write typescript to a real tmp file.
            # `script` echoes PTY output to BOTH the typescript AND its own stdout.
            # Redirect stdout to /dev/null so PTY content doesn't leak into this
            # script's stdout (which is the JSON output read by audit.py).
            # We read the output from the typescript file $_ts instead.
            if [ ! -s "$_hr_file" ]; then
                _ts="/tmp/_swts_${_ip//./_}"
                rm -f "$_ts"
                timeout 32 script -q \
                    -c "timeout 25 '$_swarmctl' -d '$_ip' -Q healthreport" \
                    "$_ts" >/dev/null 2>/dev/null || true
                # Use if/then (not &&) to avoid set -e aborting on empty file
                if [ -s "$_ts" ]; then
                    cp "$_ts" "$_hr_file"
                fi
                rm -f "$_ts"
            fi

            if [ -s "$_hr_file" ]; then
                # swarmctl adds a header line and a footer line around the JSON.
                # sed '1d;$d' strips them.  ANSI codes are stripped next.
                # python3 raw_decode() finds the first '{' and stops at the end
                # of the valid JSON object, ignoring any remaining trailing text.
                _hr_json=$(sed '1d;$d' "$_hr_file" \
                    | sed 's/\x1b\[[0-9;?]*[mGKHFJA-Za-z]//g; s/\r//g' \
                    | python3 -c "
import sys,json
text=sys.stdin.read()
start=text.find('{')
if start<0: sys.exit(1)
obj,_=json.JSONDecoder().raw_decode(text[start:])
print(json.dumps(obj))
" 2>/dev/null || true)
                [ -z "$_hr_json" ] && _hr_json="null"
                rm -f "$_hr_file"
            fi

            [ -n "$_sn" ] && _sn="${_sn},"
            _sn="${_sn}{\"ip\":\"${_ip}\",\"status\":\"$(jq_escape "$_st")\",\"uptime\":\"$(jq_escape "$_ut")\",\"avail_pct\":\"$(jq_escape "$_av")\",\"used\":\"$(jq_escape "$_us")\",\"max\":\"$(jq_escape "$_mx")\",\"streams\":\"$(jq_escape "$_sr")\",\"version\":\"$(jq_escape "$_vr")\",\"errors\":\"$(jq_escape "$_er")\",\"health_report\":${_hr_json}}"
        done

        [ -n "$_sn" ] && DISCOVERED_STORAGE_NODES="[${_sn}]"
    fi
fi

# ─── Discovery: Elasticsearch cluster name + members via API ──────────────────

DISCOVERED_ES_NODES="[]"
ES_CLUSTER_NAME=""
_es_qip=""

# Resolve which ES IP to query.
# Strategy: try 127.0.0.1 first, then any local IPv4 that responds on :9200
# (DataCore ES may bind to the management interface, not lo).
# Accept HTTP 200 OR 401 (auth-protected but running ES).
# Resolve ES bind IP. Accept HTTP 200 or 401 (auth-protected but alive).
_es_responds() {
    local _code
    _code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 3 "http://${1}:9200" 2>/dev/null || true)
    case "$_code" in 200|401) return 0 ;; esac
    return 1
}

if port_listening 9200 && command -v curl &>/dev/null; then
    # 1. Try 127.0.0.1 (ES bound to lo or 0.0.0.0)
    if _es_responds "127.0.0.1"; then
        _es_qip="127.0.0.1"
    fi
    # 2. Read network.host from elasticsearch.yml (most reliable for interface-bound ES)
    if [ -z "$_es_qip" ] && [ -f /etc/elasticsearch/elasticsearch.yml ]; then
        _nh=$(grep -E '^\s*network\.host\s*:' /etc/elasticsearch/elasticsearch.yml 2>/dev/null \
            | head -1 | sed 's/.*:\s*//' | tr -d "\"' \[\]" | cut -d, -f1 | xargs 2>/dev/null || true)
        if echo "$_nh" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' && _es_responds "$_nh"; then
            _es_qip="$_nh"
        fi
    fi
    # 3. Scan all local non-loopback IPs as fallback
    if [ -z "$_es_qip" ]; then
        _local_ips=$(ip -4 addr show 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | grep -v '^127\.' || true)
        for _lip in $_local_ips; do
            if _es_responds "$_lip"; then
                _es_qip="$_lip"
                break
            fi
        done
    fi
fi
# 4. GW-provided ES IPs (cross-node discovery from GW config)
if [ -z "$_es_qip" ]; then
    _es_qip=$(echo "$GW_ES_IPS" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
fi

if [ -n "$_es_qip" ] && command -v curl &>/dev/null; then
    # Cluster name from root endpoint
    _es_root=$(curl -sf --connect-timeout 5 "http://${_es_qip}:9200" 2>/dev/null || true)
    if [ -n "$_es_root" ]; then
        # Extract "cluster_name":"value" — pure bash, no jq needed
        _cn="${_es_root#*\"cluster_name\":\"}"
        _cn="${_cn%%\"*}"
        [ -n "$_cn" ] && ES_CLUSTER_NAME="$_cn"
    fi

    # Node list
    _cat_raw=$(curl -sf --connect-timeout 5 \
        "http://${_es_qip}:9200/_cat/nodes?h=ip,name" 2>/dev/null || true)
    if [ -n "$_cat_raw" ]; then
        _ens=$(echo "$_cat_raw" \
            | awk '{printf "{\"ip\":\"%s\",\"name\":\"%s\"},", $1, $2}' \
            | sed 's/,$//' || true)
        [ -n "$_ens" ] && DISCOVERED_ES_NODES="[${_ens}]"
    fi
fi

# ES cluster health + enriched data for modal display
ES_CAT_HEALTH=""
ES_CAT_INDICES=""
ES_CAT_NODES=""
ES_NODE_STATS=""
ES_CAT_ALLOC=""
if [ -n "$_es_qip" ] && command -v curl &>/dev/null; then
    ES_CAT_HEALTH=$(curl -sf --connect-timeout 5 \
        "http://${_es_qip}:9200/_cat/health?v" 2>/dev/null || true)
    ES_CAT_INDICES=$(curl -sf --connect-timeout 10 \
        "http://${_es_qip}:9200/_cat/indices?v&s=store.size:desc" 2>/dev/null || true)
    ES_CAT_NODES=$(curl -sf --connect-timeout 5 \
        "http://${_es_qip}:9200/_cat/nodes?v&h=name,ip,master,role,cpu,ram.percent,heap.percent,fielddataMemory,queryCacheMemory" \
        2>/dev/null || true)
    ES_NODE_STATS=$(curl -sf --connect-timeout 15 \
        "http://${_es_qip}:9200/_nodes/stats/indices/search,indexing" 2>/dev/null || true)
    ES_CAT_ALLOC=$(curl -sf --connect-timeout 5 \
        "http://${_es_qip}:9200/_cat/allocation?v&s=disk.avail:desc" 2>/dev/null || true)
fi

# ES data disk type — detect SSD vs HDD and latency metrics
ES_DISK_INFO="null"
_es_data_path=""
if [ -f /etc/elasticsearch/elasticsearch.yml ]; then
    _es_data_path=$(grep -E '^\s*path\.data\s*:' /etc/elasticsearch/elasticsearch.yml 2>/dev/null \
        | head -1 | sed 's/.*:\s*//' | tr -d "\"'" | xargs 2>/dev/null || true)
fi
[ -z "$_es_data_path" ] && _es_data_path="/var/lib/elasticsearch"
if [ -d "$_es_data_path" ]; then
    _es_dev=$(df "$_es_data_path" 2>/dev/null | awk 'NR==2{print $1}')
    if [ -n "$_es_dev" ]; then
        # Strip partition suffix (sda1 → sda, nvme0n1p1 → nvme0n1)
        _es_devname=$(basename "$_es_dev" | sed 's/p[0-9]*$//; s/[0-9]*$//')
        _rotational=$(cat "/sys/block/${_es_devname}/queue/rotational" 2>/dev/null || echo "")
        _scheduler=$(cat "/sys/block/${_es_devname}/queue/scheduler" 2>/dev/null | grep -oP '\[.*?\]' | tr -d '[]' || echo "")
        _size_sec=$(cat "/sys/block/${_es_devname}/size" 2>/dev/null || echo "0")
        _size_gb=$(( (_size_sec * 512) / 1024 / 1024 / 1024 ))
        # Disk stat: fields 4 (read_ticks ms) and 8 (write_ticks ms) give cumulative IO time
        _stat_line=$(cat "/sys/block/${_es_devname}/stat" 2>/dev/null | tr -s ' ' | sed 's/^ //' || echo "")
        _read_ios=$(echo "$_stat_line" | cut -d' ' -f1)
        _read_ms=$(echo "$_stat_line" | cut -d' ' -f4)
        _write_ios=$(echo "$_stat_line" | cut -d' ' -f5)
        _write_ms=$(echo "$_stat_line" | cut -d' ' -f8)
        # iostat-style average: ms/io (0 if no IOs yet)
        _avg_read_ms=0; _avg_write_ms=0
        [ "${_read_ios:-0}" -gt 0 ] 2>/dev/null && _avg_read_ms=$(( _read_ms / _read_ios )) || true
        [ "${_write_ios:-0}" -gt 0 ] 2>/dev/null && _avg_write_ms=$(( _write_ms / _write_ios )) || true
        ES_DISK_INFO="{\"path\":\"$(jq_escape "$_es_data_path")\",\"device\":\"$(jq_escape "$_es_dev")\",\"type\":\"$([ "$_rotational" = "0" ] && echo "SSD" || echo "HDD")\",\"rotational\":\"$(jq_escape "$_rotational")\",\"scheduler\":\"$(jq_escape "$_scheduler")\",\"size_gb\":${_size_gb:-0},\"avg_read_latency_ms\":${_avg_read_ms:-0},\"avg_write_latency_ms\":${_avg_write_ms:-0}}"
    fi
fi

# Parse elasticsearch.yml: cluster.name + seed hosts (works on ES nodes)
ES_SEED_HOSTS="[]"
if [ -f /etc/elasticsearch/elasticsearch.yml ]; then
    # cluster.name from local config (authoritative on ES nodes)
    _yml_cn=$(grep -E '^\s*cluster\.name\s*:' /etc/elasticsearch/elasticsearch.yml 2>/dev/null \
        | head -1 | sed 's/.*:\s*//' | tr -d '"'"'" | xargs || true)
    [ -n "$_yml_cn" ] && ES_CLUSTER_NAME="$_yml_cn"

    _seeds=$(grep -A10 "discovery.seed_hosts\|seed_hosts" \
        /etc/elasticsearch/elasticsearch.yml 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?' \
        | awk '{printf "\"%s\",", $1}' \
        | sed 's/,$//' || true)
    [ -n "$_seeds" ] && ES_SEED_HOSTS="[${_seeds}]"
fi

# ─── Installed RPM packages (Swarm ecosystem + infra) ────────────────────────
# Patterns cover all caringo/* DataCore packages + infra (haproxy, keepalived,
# elasticsearch, redis, memcached, java/openjdk).

INSTALLED_PACKAGES="[]"
if command -v rpm &>/dev/null; then
    _pkg_patterns="^(haproxy|keepalived|caringo-|elasticsearch|redis|memcached|java-|jre-|jdk-|java_|openjdk|swarm|rabbitmq|prometheus)"
    _pkgs=$(rpm -qa --queryformat '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n' 2>/dev/null \
        | grep -iE "$_pkg_patterns" \
        | sort -u \
        | awk -F'\t' '{
            gsub(/"/,"\\\"", $1); gsub(/"/,"\\\"", $2)
            gsub(/"/,"\\\"", $3); gsub(/"/,"\\\"", $4)
            printf "{\"name\":\"%s\",\"version\":\"%s\",\"release\":\"%s\",\"arch\":\"%s\"},",
                $1, $2, $3, $4
          }' \
        | sed 's/,$//' || true)
    [ -n "$_pkgs" ] && INSTALLED_PACKAGES="[${_pkgs}]"
fi

# ─── Log collection (last 24h per detected role) ─────────────────────────────
# _has_role: check if ROLES JSON contains a given role string
_has_role() { printf '%s' "$ROLES" | grep -q "\"role\":\"$1\""; }

# _collect_log UNIT GLOB...
#   1. Try journald unit (time-filtered to last 24h)
#   2. Fallback: file globs, most-recent-first
#   3. Deduplicate if > 50 KB by stripping timestamps and counting occurrences
_collect_log() {
    local unit="$1"; shift
    local cap=102400  # 100 KB hard cap
    local raw=""

    if [ -n "$unit" ] && command -v journalctl &>/dev/null; then
        raw=$(journalctl -u "$unit" --since "24 hours ago" \
              -o short-iso --no-pager -q 2>/dev/null | head -c $cap || true)
    fi

    if [ -z "$raw" ]; then
        local glob f
        for glob in "$@"; do
            for f in $glob; do
                [ -f "$f" ] || continue
                # Lines from last 24h: grep by today/yesterday date prefix
                local today yesterday
                today=$(date -u '+%Y-%m-%d' 2>/dev/null || true)
                yesterday=$(date -u -d '1 day ago' '+%Y-%m-%d' 2>/dev/null \
                         || date -u -v-1d '+%Y-%m-%d' 2>/dev/null || true)
                if [ -n "$today" ]; then
                    raw=$(grep -E "^(${today}|${yesterday})" "$f" 2>/dev/null \
                          | head -c $cap || true)
                fi
                [ -z "$raw" ] && raw=$(tail -n 5000 "$f" 2>/dev/null | head -c $cap || true)
                [ -n "$raw" ] && break
            done
            [ -n "$raw" ] && break
        done
    fi

    [ -z "$raw" ] && return 0

    # Deduplicate: strip timestamp prefix, count, sort by frequency desc
    if [ ${#raw} -gt 51200 ]; then
        raw=$(printf '%s\n' "$raw" | awk '
        {
            msg = $0
            sub(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.0-9]*[+-][0-9:]+ /, "", msg)
            sub(/^[A-Z][a-z][a-z]  ?[0-9]+ [0-9]{2}:[0-9]{2}:[0-9]{2} [^ ]+ /, "", msg)
            if (length(msg) > 0) count[msg]++
        }
        END { for (m in count) printf "[x%d] %s\n", count[m], m }
        ' 2>/dev/null | sort -t']' -k1 -rn | head -500 \
          || printf '%s' "$raw" | tail -c 51200)
    fi

    printf '%s' "$raw"
}

_LOG_HAPROXY=""
_LOG_GATEWAY=""
_LOG_LCS_SERVER=""
_LOG_ES=""
_LOG_CASTOR=""
_LOG_SCS=""
_LOG_REDIS=""

_has_role "HAPROXY"              && _LOG_HAPROXY=$(     _collect_log "haproxy"         "/var/log/haproxy.log" "/var/log/haproxy/*.log")
_has_role "CONTENT_GATEWAY"      && _LOG_GATEWAY=$(     _collect_log "caringo-gateway" "/var/log/datacore/gateway*.log" "/var/log/datacore/contentgateway*.log" "/var/log/caringo/gateway*.log" "/var/log/datacore/*.log")
_has_role "LISTING_CACHE_SERVER" && _LOG_LCS_SERVER=$(  _collect_log "caringo-gateway" "/var/log/datacore/lcs*.log" "/var/log/datacore/listingcache*.log" "/var/log/caringo/gateway*.log")
# LCS server and gateway share the same service — reuse if empty
_has_role "LISTING_CACHE_SERVER" && [ -z "$_LOG_LCS_SERVER" ] && _LOG_LCS_SERVER="$_LOG_GATEWAY"
_has_role "ELASTICSEARCH"        && _LOG_ES=$(          _collect_log "elasticsearch"   "/var/log/elasticsearch/*.log" "/var/log/datacore/elasticsearch*.log")
# CASTOR: on SCS (syslog server) or on a bare storage node
_has_role "SCS"                  && _LOG_CASTOR=$(      _collect_log "castor"          "/var/log/caringo/castor.log" "/var/log/datacore/castor*.log" "/var/log/caringo/*.log")
_has_role "UNKNOWN"              && [ -z "$_LOG_CASTOR" ] && \
    _LOG_CASTOR=$(                                       _collect_log "castor"          "/var/log/caringo/castor.log" "/var/log/datacore/castor*.log" "/var/log/caringo/*.log")
_has_role "SCS"                  && _LOG_SCS=$(         _collect_log "scs"             "/var/log/datacore/scs*.log" "/var/log/caringo/scs*.log")
_has_role "LISTING_CACHE"        && _LOG_REDIS=$(       _collect_log "redis-server"    "/var/log/redis/*.log" "/var/log/redis/redis*.log")

_log_entries=""
_add_log_json() {
    local role="$1" content="$2"
    [ -z "$content" ] && return
    [ -n "$_log_entries" ] && _log_entries+=","
    local _esc
    _esc=$(jq_escape "$content")
    _log_entries+="\"${role}\":\"${_esc}\""
}
_add_log_json "HAPROXY"              "$_LOG_HAPROXY"
_add_log_json "CONTENT_GATEWAY"      "$_LOG_GATEWAY"
_add_log_json "LISTING_CACHE_SERVER" "$_LOG_LCS_SERVER"
_add_log_json "ELASTICSEARCH"        "$_LOG_ES"
_add_log_json "CASTOR"               "$_LOG_CASTOR"
_add_log_json "SCS"                  "$_LOG_SCS"
_add_log_json "LISTING_CACHE"        "$_LOG_REDIS"
LOGS_JSON="{${_log_entries}}"

# ─── Output JSON ─────────────────────────────────────────────────────────────

cat <<EOF
{
  "hostname": "$(jq_escape "$HOSTNAME_VAL")",
  "os": "$(jq_escape "$OS_PRETTY")",
  "kernel": "$(jq_escape "$KERNEL")",
  "uptime_sec": $UPTIME_SEC,
  "cpu": {
    "count": $CPU_COUNT,
    "model": "$(jq_escape "$CPU_MODEL")"
  },
  "ram": {
    "total_mb": $RAM_TOTAL_MB,
    "free_mb": $RAM_FREE_MB
  },
  "disks": $DISK_JSON,
  "roles": $ROLES,
  "config_files": $CONFIG_FILES,
  "config_contents": $CONFIG_CONTENTS,
  "haproxy_vips": $HAPROXY_VIPS,
  "haproxy_backends": $HAPROXY_BACKENDS,
  "gw_config_path": "$(jq_escape "$GW_CONFIG_PATH")",
  "gw_cluster_ips": $GW_CLUSTER_IPS,
  "gw_es_ips": $GW_ES_IPS,
  "gw_lcs_ips": $GW_LCS_IPS,
  "swarmctl_path": "$(jq_escape "$_swarmctl")",
  "swarm_cluster_summary": "$(jq_escape "$SWARM_CLUSTER_SUMMARY")",
  "discovered_storage_nodes": $DISCOVERED_STORAGE_NODES,
  "es_cluster_name": "$(jq_escape "$ES_CLUSTER_NAME")",
  "discovered_es_nodes": $DISCOVERED_ES_NODES,
  "es_seed_hosts": $ES_SEED_HOSTS,
  "es_cat_health": "$(jq_escape "$ES_CAT_HEALTH")",
  "es_cat_indices": "$(jq_escape "$ES_CAT_INDICES")",
  "es_cat_nodes": "$(jq_escape "$ES_CAT_NODES")",
  "es_node_stats": "$(jq_escape "$ES_NODE_STATS")",
  "es_cat_alloc": "$(jq_escape "$ES_CAT_ALLOC")",
  "es_disk_info": $ES_DISK_INFO,
  "ntp_client_servers": $NTP_CLIENT_SERVERS,
  "syslog_targets": $SYSLOG_TARGETS,
  "keepalived_peers": $KEEPALIVED_PEERS,
  "listen_ports": $LISTEN_PORTS,
  "network_interfaces": $NETWORK_INTERFACES,
  "connections": $NET_CONNS,
  "installed_packages": $INSTALLED_PACKAGES,
  "health_report_json": null,
  "is_syslog_server": $IS_SYSLOG_SERVER,
  "is_ntp_server": $IS_NTP_SERVER,
  "is_dhcp_server": $IS_DHCP_SERVER,
  "is_pxe_server": $IS_PXE_SERVER,
  "is_rabbitmq": $IS_RABBITMQ,
  "is_prometheus": $IS_PROMETHEUS,
  "is_alertmanager": $IS_ALERTMANAGER,
  "is_grafana": $IS_GRAFANA,
  "is_content_ui": $IS_CONTENT_UI,
  "is_storage_ui": $IS_STORAGE_UI,
  "logs": $LOGS_JSON
}
EOF
