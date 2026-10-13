"""Offline acceptance of an operator file through the existing upload API.

Run in a fresh Python process. All SQLite connections are restricted to one new
temporary database; network connections and process launches are blocked.
Only aggregate results are written, never a copy of the input inventory.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import sys
import tempfile
from unittest.mock import patch


class AcceptanceFailure(ValueError):
    """Failure messages contain check names only, never operator values."""


def require(condition, message):
    if not condition:
        raise AcceptanceFailure(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON field; values withheld")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("Invalid JSON number")


def check_no_credentials(value):
    if isinstance(value, dict):
        for key, child in value.items():
            require(not any(word in key.lower() for word in (
                "password", "private_key", "passphrase", "credential", "secret", "token")),
                "Credential field detected; values withheld")
            check_no_credentials(child)
    elif isinstance(value, list):
        for child in value:
            check_no_credentials(child)
    elif isinstance(value, str):
        require(not re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", value),
                "Private key material detected; values withheld")


def check_package_records(packages):
    # Compare the complete structured version to raw, never split on the last '-'.
    for index, package in enumerate(packages, 1):
        require(all(isinstance(package.get(k), str) and package[k] for k in (
            "name", "version", "architecture", "source", "status", "raw")),
            f"Package {index}: required field missing")
        require(isinstance(package.get("license"), str), f"Package {index}: license field missing")
        expected = (f"{package['name']}-{package['version']} {package['architecture']} "
                    f"{{{package['source']}}} ({package['license']}) [installed]")
        require(package["raw"] == expected and package["status"] == "installed",
                f"Package {index}: raw/name/version/architecture/source/license/status mismatch")
    return {"records_checked": len(packages), "exact_raw_matches": len(packages),
            "architectures": dict(Counter(p["architecture"] for p in packages)),
            "nonempty_source_count": sum(bool(p["source"]) for p in packages),
            "distinct_source_count": len({p["source"] for p in packages}),
            "empty_license_count": sum(not p["license"] for p in packages)}


def install_offline_guard(database_path):
    allowed_database = database_path.resolve()

    def guard(event, args):
        if event == "sqlite3.connect":
            require(Path(str(args[0])).resolve() == allowed_database,
                    "SQLite isolation guard blocked an unexpected database")
        elif event == "socket.connect":
            # Windows asyncio creates a localhost socketpair for internal wakeups.
            # Allow only that stdlib function's own socket and bound ephemeral port.
            caller = sys._getframe(1)
            fallback = getattr(socket, "_fallback_socketpair", None)
            internal_pair = (fallback is not None and caller.f_code is fallback.__code__ and
                             args[0] is caller.f_locals.get("csock") and
                             args[1] == caller.f_locals["lsock"].getsockname()[:2] and
                             args[1][0] in {"127.0.0.1", "::1"})
            require(internal_pair, "Offline acceptance guard blocked network access")
        elif event in {"socket.getaddrinfo", "subprocess.Popen", "os.system"}:
            raise RuntimeError("Offline acceptance guard blocked network/process access")
        elif event == "open" and args and isinstance(args[0], (str, bytes, os.PathLike)):
            name = Path(os.fsdecode(args[0])).name.lower()
            require(not (name == ".env" or name.startswith(".env.") or name in {
                "id_ed25519", "id_rsa", "iotguard_ed25519"}),
                "Offline acceptance guard blocked environment/private key file access")

    sys.addaudithook(guard)


def run_acceptance(input_path, expected_count=182, expected_firmware="25.12.5"):
    require(not any(name == "app" or name.startswith("app.") for name in sys.modules),
            "Acceptance requires a fresh process before application imports")
    input_path = input_path.resolve()
    raw = input_path.read_bytes()
    require(len(raw) <= 5_000_000, "Input exceeds upload size limit")
    document = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object,
                          parse_constant=reject_constant)
    check_no_credentials(document)
    digest = hashlib.sha256(raw).hexdigest()
    runtime_dir = Path(tempfile.mkdtemp(prefix="iotguard-stage3-"))
    database_path = runtime_dir / "acceptance.sqlite3"
    require(not database_path.exists(), "Acceptance database must be new")
    install_offline_guard(database_path)
    settings = {"PYTHON_DOTENV_DISABLED": "1", "LINUXGUARD_ARCHIVE_ON_STARTUP": "0",
                "LINUXGUARD_DATABASE_URL": "sqlite:///" + str(database_path),
                "LINUXGUARD_EVENT_FILE": str(runtime_dir / "events.jsonl"),
                "REPORT_ARCHIVE_DIR": str(runtime_dir / "archives"),
                "LINUXGUARD_REPAIR_MANIFEST": "", "DEEPSEEK_API_KEY": "", "NVD_API_KEY": "",
                "LINUXGUARD_CONTROL_TOKEN": "offline-acceptance-only"}
    for name in ("VM_HOST", "VM_HOSTS", "VM_PORT", "VM_PORTS", "VM_USER", "VM_PASS", "BIONIC_CONTAINER"):
        settings[name] = ""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    with patch.dict(os.environ, settings), patch("dotenv.load_dotenv", return_value=False):
        from app import config
        config.DATA_DIR = runtime_dir / "data"
        config.DATA_DIR.mkdir()
        from app.schemas import OpenWrtExportDocument
        from jsonschema import Draft202012Validator, FormatChecker
        schema = OpenWrtExportDocument.model_json_schema()
        Draft202012Validator.check_schema(schema)
        errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document))
        require(not errors, "JSON Schema validation failed; values withheld")
        OpenWrtExportDocument.model_validate(document)
        device, software = document["device"], document["software_inventory"]
        packages = software["packages"]
        require(device["firmware"]["version"] == expected_firmware, "Unexpected firmware version")
        require(device["firmware"]["distribution"].lower() == "openwrt", "Unexpected distribution")
        require(software["raw_count"] == software["package_count"] == len(packages) == expected_count,
                "Expected/raw/parsed/actual package counts do not agree")
        require(software["parse_error_count"] == 0, "Upstream parser errors are nonzero")
        package_checks = check_package_records(packages)
        from app import models, database, main
        from fastapi.testclient import TestClient
        from sqlalchemy import create_engine, event, text
        from sqlalchemy.orm import sessionmaker
        engine = database.engine

        @event.listens_for(engine, "connect")
        def enable_foreign_keys(connection, _record):
            connection.execute("PRAGMA foreign_keys=ON")

        # The database module's early WAL connection is also isolated by the guard.
        with engine.connect() as connection:
            connection.execute(text("PRAGMA foreign_keys=ON"))
        database.Base.metadata.create_all(engine)
        factory = database.SessionLocal
        require(Path(engine.url.database).resolve() == database_path.resolve(), "Wrong engine database")

        def counts():
            with factory() as db:
                return {"assets": db.query(models.LinuxAsset).count(),
                        "packages": db.query(models.AssetPackage).count(),
                        "services": db.query(models.AssetService).count(),
                        "connections": db.query(models.DeviceConnection).count(),
                        "vulnerabilities": db.query(models.VulnerabilityInfo).count(),
                        "openwrt_advisories": db.query(models.OpenWrtAdvisory).count(),
                        "matches": db.query(models.VulnerabilityMatch).count(),
                        "runtime_events": db.query(models.RuntimeEvent).count()}

        def override_db():
            with factory() as db:
                yield db

        main.app.dependency_overrides[database.get_db] = override_db
        headers = {"X-Control-Token": settings["LINUXGUARD_CONTROL_TOKEN"]}
        before = counts()
        require(all(v == 0 for v in before.values()), "Temporary database is not empty")
        try:
            with patch.object(main, "SessionLocal", factory), patch.object(main, "init_db", lambda: None), \
                    redirect_stdout(io.StringIO()), TestClient(main.app) as client:
                response = client.post("/api/assets/upload", files={"file": ("inventory.json", raw, "application/json")},
                                       headers=headers)
                require(response.status_code == 200, f"Initial upload failed: HTTP {response.status_code}")
                result = response.json()
                asset_id = result["asset"]["id"]
                require(result["package_parse_stats"]["parsed_count"] == expected_count,
                        "Import parser count mismatch")
                after_first = counts()
                response = client.post("/api/assets/upload", files={"file": ("inventory.json", raw, "application/json")},
                                       headers=headers)
                require(response.status_code == 200, f"Repeated upload failed: HTTP {response.status_code}")
                require(response.json()["asset"]["id"] == asset_id, "Asset ID changed on repeat upload")
                after_repeat = counts()
                require(after_repeat == after_first, "Repeat upload changed row counts")
                require(after_repeat["assets"] == 1 and after_repeat["packages"] == expected_count,
                        "Unexpected imported row counts")
                require(all(after_repeat[k] == 0 for k in after_repeat if k not in {"assets", "packages"}),
                        "Upload created unexpected connection/scan/runtime rows")
                response = client.get(f"/api/assets/{asset_id}")
                require(response.status_code == 200, "API asset readback failed")
                api_asset = response.json()
                require(len(client.get("/api/assets").json()) == 1, "Asset list readback mismatch")
        finally:
            main.app.dependency_overrides.clear()
            engine.dispose()

        # Reopen the physical SQLite file with a distinct engine and fresh session.
        read_engine = create_engine("sqlite:///" + str(database_path))
        with read_engine.connect() as connection:
            foreign_key_errors = connection.execute(text("PRAGMA foreign_key_check")).all()
            require(not foreign_key_errors, "Foreign key violations found")
        expected_packages = {p["name"]: (p["version"], p["architecture"], "apk") for p in packages}
        expected_metadata = {p["name"]: (p["source"], p["license"], p["status"]) for p in packages}

        def check_snapshot(asset, saved_packages, metadata):
            require(saved_packages == expected_packages, "Package name/full version/architecture readback mismatch")
            actual_metadata = {p["name"]: (p["source"], p["license"], p["status"])
                               for p in metadata["package_metadata"]}
            require(actual_metadata == expected_metadata, "Package provenance readback mismatch")
            require(asset["distribution"] == "openwrt" and asset["os_name"] == "OpenWrt" and
                    asset["os_version"] == asset["firmware_version"] == expected_firmware and
                    asset["kernel_version"] == device["kernel"] and
                    asset["device_model"] == device["board_name"] and asset["architecture"] == "x86_64" and
                    asset["inventory_external_id"] == "openwrt-json:" + document["asset_id"] and
                    asset["inventory_complete"] is True and asset["inventory_sha256"] == digest,
                    "Asset field readback mismatch")
            require(asset["ip_address"] == document.get("management", {}).get("ip_address", device.get("ip_address", "")),
                    "Management address readback mismatch")
            require(metadata["device"]["firmware"] == device["firmware"] and
                    metadata["device"]["model"] == device["model"] and
                    metadata["management"] == document.get("management") and
                    metadata["integrity"] == document.get("integrity") and
                    metadata["ssh_identity_verified_by_platform"] is False,
                    "Device/provenance readback mismatch")

        check_snapshot(api_asset, {p["package_name"]: (p["package_version"], p["architecture"], p["package_manager"])
                                  for p in api_asset["packages"]}, api_asset["inventory_metadata"])
        read_factory = sessionmaker(bind=read_engine)
        with read_factory() as db:
            asset = db.get(models.LinuxAsset, asset_id)
            rows = db.query(models.AssetPackage).all()
            require(len(rows) == expected_count and all(p.asset_id == asset_id for p in rows),
                    "Software package association mismatch")
            metadata = json.loads(asset.inventory_metadata_json)
            fields = {k: getattr(asset, k) for k in ("distribution", "os_name", "os_version", "firmware_version",
                "kernel_version", "device_model", "architecture", "inventory_external_id", "inventory_complete",
                "inventory_sha256", "ip_address")}
            check_snapshot(fields, {p.package_name: (p.package_version, p.architecture, p.package_manager) for p in rows}, metadata)
            saved_time = asset.inventory_collected_at.replace(tzinfo=timezone.utc)
            require(saved_time == datetime.fromisoformat(document["generated_at"]).astimezone(timezone.utc),
                    "Inventory timestamp readback mismatch")
            identity_source = asset.identity_source
        read_engine.dispose()
        require(hashlib.sha256(input_path.read_bytes()).hexdigest() == digest, "Input inventory changed")

    summary = {"status": "PASS", "executed_at": datetime.now(timezone.utc).isoformat(),
               "input_file": str(input_path), "input_bytes": len(raw), "input_sha256": digest,
               "temporary_database": str(database_path), "schema_validation": "PASS",
               "schema_version": document["schema_version"], "firmware": device["firmware"],
               "asset_external_id": document["asset_id"], "registered_asset_id": asset_id,
               "inventory_counts": {"raw": software["raw_count"], "declared_parsed": software["package_count"],
                                    "actual_array": len(packages), "import_parser": result["package_parse_stats"]["parsed_count"],
                                    "parse_errors": software["parse_error_count"]},
               "package_checks": package_checks, "before": before,
               "after_first": after_first, "after_repeat": after_repeat,
               "checks": {name: "PASS" for name in ("asset_registration", "package_foreign_keys",
                   "repeat_import_idempotency", "api_readback", "new_engine_readback", "full_versions_preserved",
                   "package_provenance_preserved", "timestamp_preserved", "input_unchanged", "offline_database_isolation")},
               "identity_source": identity_source, "ssh_identity_verified": False,
               "source_file_hashes": "declared_only_external_source_files_unavailable",
               "cve_data_ready": True, "cve_matching_executed": False,
               "limitations": ["Source file hashes cannot be verified without original Ubuntu files",
                   "Offline upload does not verify SSH identity; no MAC is supplied",
                   "No service/runtime evidence or OpenWrt applicability intelligence was imported",
                   "Package version matching is not vulnerability confirmation"]}
    summary_path = runtime_dir / "acceptance_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(run_acceptance(args.inventory), ensure_ascii=False, indent=2))
    except Exception as exc:
        # Do not echo exception text: libraries can embed operator input values.
        print(json.dumps({"status": "FAIL", "error_type": type(exc).__name__,
                          "detail": str(exc) if isinstance(exc, AcceptanceFailure) else
                          "Offline acceptance failed; input and credentials withheld"}))
        raise SystemExit(1)
