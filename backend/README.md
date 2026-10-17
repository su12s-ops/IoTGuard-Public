# LinuxGuard Backend

FastAPI + SQLAlchemy + SQLite backend for the LinuxGuard demo platform.

## Start

```powershell
cd <PROJECT_ROOT>\代码\backend
python -m pip install -r requirements.txt
python scripts\sync_real_intel.py --keyword linux --days 30 --limit 100
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Unified four-agent production

Set the key in the backend process environment. Do not put it in frontend files.

```powershell
$env:DEEPSEEK_API_KEY = "your-key"
$env:DEEPSEEK_MODEL = "deepseek-v4-flash"
$env:LINUXGUARD_UNIFIED_PIPELINE = "on"
$env:LINUXGUARD_ENABLE_DEVICE_REPAIR = "0"
$env:LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR = "0"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The sole LangGraph pipeline uses asset_investigator → vulnerability_analyst ∥ runtime_analyst → decision_planner. POST /api/analysis/runs requires the control token, processes one object by default (maximum four), and never falls back to a retired LLM pipeline. off/shadow disable formal analysis.

Investigation requests require separate authorization for the existing fixed read-only collector. Fresh INV evidence can resume the same formal pipeline. Historical inactive objects use /api/analysis/risks/{id}/historical-analysis for drafts and /historical-adjudication for an authorized operator decision; drafts never reactivate a risk. See IOTGUARD_M5_MIGRATION_CONTRACT_V2.md at the repository root. Device writes remain independently gated by exact-plan approval and both write switches.

## Key Endpoints

- `GET /api/health`
- `GET /api/dashboard/summary`
- `GET /api/vulnerabilities`
- `POST /api/vulnerabilities/sync-real`
- `GET /api/assets`
- `POST /api/assets/upload`
- `POST /api/matching/run`
- `GET /api/matching/results`
- `POST /api/risk/calculate`
- `GET /api/risk/ranking`
- `POST /api/remediation/generate`
- `GET /api/remediation/tasks`
- `GET /api/reports/summary.md`
- `GET /api/reports/summary.json`
- `GET /api/reports/summary.csv`

## IoT upgrade (0.2)

See the project-level IOT_UPGRADE_GUIDE.md for device registration, environment variables, collector heartbeat and repair-manifest configuration. Startup preserves data by default.

- /api/iot: connections, SSH collection, bounded discovery, observations and source-linked OpenWrt applicability.
- /api/runtime/assets/{id}: coverage, process timeline and before/after comparison.
- /api/runtime/sensors/heartbeat: control-token protected health ingestion.
- /api/harness: persistent investigation and approved repair tasks, verification, rollback and recovery.

Run python -m pytest -q using isolated fixtures. No test connects to real hardware. Run python scripts/validate_repair_manifest.py to check a locally configured manifest without device access.
