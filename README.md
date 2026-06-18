# ARCIS-SWARM — Infrastructure Audit & Topology Mapper

A self-hosted web application for auditing, role-detection, and dynamic topology mapping of multi-tier **DataCore SWARM** (formerly Caringo) infrastructure.

Connects via SSH to each server, runs a non-destructive Bash audit script, and produces an interactive SVG network diagram with detected roles, subnet buses, storage metrics, and live connection flows.

---

## Features

- **Automated SSH audit** — pushes and executes a read-only Bash script on each node, no agent required
- **Role detection** — identifies HAProxy, Content Gateway, SCS, Elasticsearch, Listing Cache, Foundation DB, Storage Nodes (Castor), SwarmFS, Storage UI, Content UI, CSN Platform, Telemetry
- **Dynamic SVG diagram** — layered topology map with subnet bus lines, IP badges, storage capacity bars, connection overlay
- **Inventory management** — browser UI to manage SSH credential profiles and server list
- **Local-first storage** — single `inventory.json` file, no external database
- **Discovered nodes** — additional storage nodes and ES peers found via swarmctl/ES API are automatically added to the map

---

## Quick Start — Docker

**Requirements:** Docker 24+, Docker Compose v2

```bash
git clone https://github.com/gaetanmarais/SWARM-AUDIT.git
cd SWARM-AUDIT

# Create your inventory from the sample
cp inventory.sample.json inventory.json

# Build and run
docker compose up -d
```

Open **http://localhost:8099**

---

## Quick Start — Docker (no Compose)

```bash
docker build -t swarm-audit .

docker run -d \
  --name swarm-audit \
  --restart unless-stopped \
  -p 8099:8000 \
  -v "$(pwd)/inventory.json:/app/inventory.json" \
  -v "$(pwd)/dumps:/app/dumps" \
  swarm-audit
```

---

## Configuration

### 1. inventory.json

Copy `inventory.sample.json` to `inventory.json` before first run. The app reads and writes this file at runtime.

The file is **excluded from git** (`.gitignore`) — it may contain SSH credentials.

Structure:

```json
{
  "credentials": [
    {
      "id": "cred-default",
      "name": "root-ssh",
      "username": "root",
      "password": "changeme",
      "private_key": null,
      "port": 22,
      "is_default": true
    }
  ],
  "servers": [
    {
      "id": "srv-01",
      "name": "haproxy-01",
      "ip": "10.0.0.1",
      "credential_id": null
    }
  ]
}
```

- `credential_id: null` — uses the credential flagged `is_default: true`
- `private_key` — paste the full PEM key as a single string with `\n` separators, or manage via the UI

### 2. Port

Default host port: **8099** (maps to container port 8000). Change in `docker-compose.yml`:

```yaml
ports:
  - "8099:8000"   # change 8099 to any free port
```

### 3. Data persistence

Two paths are volume-mounted:

| Path (host) | Container | Purpose |
|---|---|---|
| `./inventory.json` | `/app/inventory.json` | Credential + server config |
| `./dumps/` | `/app/dumps/` | Raw audit JSON per node |

The `dumps/` directory is created automatically on first audit.

---

## Usage

1. **Credentials** tab → add SSH credential profiles (password or private key)
2. **Servers** tab → add servers (name, IP, credential profile)
3. Click **Run Audit** → SSH to each server in parallel, collect system info
4. Click **Diagram** tab → view the topology SVG
5. Click any node tile → Details modal (roles, specs, packages, connections)
6. Click **JSON** on a tile → raw audit dump for that node

### Diagram controls

- **+/−** buttons or mouse wheel → zoom
- Click-drag → pan
- **⊙** → reset zoom
- Node tile click → Details modal
- Colored arrows on diagram → live TCP connections between nodes

---

## Detected Roles

| Role | Detection criteria |
|---|---|
| `HAPROXY` | `haproxy` process or listening port 80/443 |
| `CONTENT_GATEWAY` | `caringo-gateway` / `content-gateway` service |
| `SCS` | `swarm-scs` / `caringo-scs` package or process |
| `ELASTICSEARCH` | Java process on port 9200 |
| `LISTING_CACHE` | `redis-server` / `memcached` process |
| `LISTING_CACHE_SERVER` | `caringo-listingcache` service |
| `STORAGE_NODE` | `caringo-node` process or SNMP health report |
| `FOUNDATION_DB` | `fdbserver` process or `/etc/foundationdb/fdb.cluster` |
| `STORAGE_UI` | `caringo-storage-webui` package |
| `CONTENT_UI` | `caringo-gateway-webui` / `caringo-contentportal` |
| `SWARMFS` | `caringo-swarmfs` / `swarm-nfs` package |
| `CSN_PLATFORM` | `caringo-csn` / `swarm-scs` package |
| `TELEMETRY` | `swarm-telemetry` / `prometheus` package |
| `UNKNOWN` | No matching criteria found |

---

## Architecture

```
Browser
  └── frontend/index.html   (SPA — vanilla JS + TailwindCSS CDN)
        │
        └── FastAPI (backend/main.py)
              ├── /api/audit/run       — SSH audit via asyncssh
              ├── /api/diagram/svg     — SVG topology generator
              ├── /api/inventory/*     — CRUD for credentials + servers
              └── /api/audit/dump/:id  — raw audit JSON
```

- **audit engine** (`backend/audit.py`) — async SSH per node, pushes `scripts/audit.sh`, parses JSON output
- **SVG generator** (`backend/svg_gen.py`) — pure Python SVG output, no external rendering lib
- **storage** — `inventory.json` read/written by FastAPI at runtime

---

## Requirements (SSH target nodes)

The audit script requires on each audited server:
- `bash`
- Standard tools: `ss` or `netstat`, `df`, `free`, `uname`, `uptime`
- `dpkg` (Debian/Ubuntu) or `rpm` (RHEL/CentOS) for package detection
- SSH access with the configured credential

No agent, no daemon, no persistent changes on the target.

---

## Deployment — Proxmox LXC

For deployment in a Proxmox LXC container instead of Docker:

```bash
# On the Proxmox host
pct create 200 local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
  --hostname arcis-swarm --cores 2 --memory 512 --rootfs local-lvm:8 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp --unprivileged 1

pct start 200

# Install dependencies inside LXC
pct exec 200 -- bash -c "
  apt-get update && apt-get install -y python3 python3-venv openssh-client &&
  mkdir -p /opt/arcis-swarm
"

# Copy files
for f in backend frontend scripts Dockerfile docker-compose.yml; do
  pct push 200 ./$f /opt/arcis-swarm/$f --recursive
done

# Create venv and install
pct exec 200 -- bash -c "
  cd /opt/arcis-swarm &&
  python3 -m venv venv &&
  venv/bin/pip install -r backend/requirements.txt
"

# Create systemd service
cat <<'EOF' | pct exec 200 -- tee /etc/systemd/system/arcis-swarm.service
[Unit]
Description=ARCIS-SWARM Audit
After=network.target

[Service]
WorkingDirectory=/opt/arcis-swarm
ExecStart=/opt/arcis-swarm/venv/bin/uvicorn main:app \
  --host 0.0.0.0 --port 8000 --app-dir /opt/arcis-swarm/backend
Restart=always
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

pct exec 200 -- systemctl enable --now arcis-swarm
```

---

## License

MIT
