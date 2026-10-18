# IoTGuard Deployment

Scope: [current product and device acceptance baseline](IOTGUARD_PRODUCT_POSITIONING.md). The latest source adds `/api/devices/business/overview` and makes the IoT workbench the default frontend route (`/soc` retains the SOC). Deploy backend and frontend together; old running containers do not automatically load these changes. A successful build does not establish device connectivity or repair acceptance.

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

If a stale remote SSH listener occupies the default tunnel port without forwarding requests, inspect it before restarting the runner. Set `IOTGUARD_COLLECTION_TUNNEL_PORT` to an available unprivileged port (1024–65535) before starting the supervisor; the remote loopback backend URL and reverse forwarding use the same value. The current recovered session uses 18446. Preserve this setting when restarting that supervisor. Do not start a second supervisor alongside the existing one.

## Deployment verification, 2026-10-19

Application revision `831488d` is running on the live host API (8000), Docker API (18000), and Docker frontend (18080). Both Docker containers passed health checks; the SPA root, `/soc`, `/devices`, referenced entry assets, and the new business overview API returned HTTP 200. Live and Docker databases were backed up before restart and remain independent.

The configured registry mirror rejected base-image metadata requests with HTTP 403. Deployment therefore reused the existing local application images as runtime bases, copied the current backend application/migrations/collectors and locally built frontend dist into new labeled images, and recreated services with `--no-build`. This is an incremental application deployment, not a fresh dependency rebuild. Local build recipes and detailed receipts are preserved under ignored `reports/deploy-20261019/`. The API starts directly through uvicorn and the application lifespan, avoiding the legacy launcher’s sample-data cleanup.

The live collection node recovered after a stale reverse tunnel was bypassed. OpenWrt completed a fresh authenticated inventory collection: release 25.12.6, kernel 6.12.112, 182 packages, complete inventory. Its logread sensor resumed reporting. Zephyr QEMU returned HTTP 200 from `/api/system`; the live platform refresh verified RTOS 4.4.2, application 0.3.0-iotguard and the device identity endpoint. These are connectivity and collection results, not vulnerability repair acceptance. The Docker frontend remains a snapshot verification UI and does not display live device refreshes.
