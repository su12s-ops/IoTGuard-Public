# IoTGuard Deployment

The supported product entry point is Docker Compose. Copy `backend/.env.example` to a local environment file, set the control token, and keep both repair flags at `0`. The compose file binds the API to `127.0.0.1:18000` and the nginx SPA to `127.0.0.1:18080`; override these ports only on a trusted local reverse proxy.

`docker compose build --build-arg VCS_REF=$(git rev-parse HEAD) --build-arg BUILD_DATE=$(date -u +%FT%TZ)` builds the API and nginx images. `docker compose up -d` starts a non-root API and an unprivileged nginx worker with a separate named database volume. The API image contains only application code, migrations, collector scripts, and the non-secret configuration template. Device keys, node tokens, databases, and local archives stay outside the image.

Collection nodes and Falco remain external to Docker. They authenticate through the existing registered-node protocol. OpenWrt logread scheduling is disabled when `LINUXGUARD_OPENWRT_LOG_CONNECTION_IDS` is empty; enabling it requires already-authorized connection IDs and remains read-only, bounded to two attempts per interval with persisted deduplication.

Verify `http://127.0.0.1:18080/`, a deep SPA route, `/api/health`, and the four health layers independently: backend, collection node, sensors, and fresh runtime evidence.

PowerShell equivalent (run from the repository root after configuring the local `backend/.env.docker`):

```powershell
$env:IOTGUARD_BUILD_REVISION = git rev-parse HEAD
$env:IOTGUARD_BUILD_DATE = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
docker compose build
docker compose up -d
docker compose ps
Invoke-RestMethod http://127.0.0.1:18000/api/health
```

Read the OCI `org.opencontainers.image.revision` and `created` labels with `docker image inspect`; `/api/health` returns the backend build metadata. A documentation-only final commit still needs a label rebuild to describe the final HEAD accurately.

The delivered verification database is an independent SQLite backup in the Docker named volume. It is a point-in-time copy of the host's evidence, not a second live production database. No production node token, model key or device key is injected into the verification deployment, and periodic collection is disabled there. Historical node heartbeats will become stale; the Docker UI must not be presented as the live device collection service. Live devices continue to send to the existing host backend on port8000. Never mount its database file into a second worker.

On the authorized host, `python backend/scripts/restore_collection_node.py start --supervise` reuses the existing SSH/key/receipt scope and restarts the existing pull runner after a disconnect, with bounded backoff. It does not install a host boot service. After host reboot the backend and supervisor must be started again. Stop the supervisor before its SSH child when intentionally stopping it. Falco remains an existing Linux systemd service with Restart=always. OpenWrt logread runs every60 seconds in this acceptance configuration, using connection1 only. It reads a ring buffer, preserves raw LOG receipts and deduplicates across runs/restarts; overwritten ring entries and kernel drops cannot be proven zero. Generic fresh runtime status can be satisfied by Falco alone: always inspect each sensor and asset separately.
