"""Early, dependency-free guard before a collection node can open SQLite."""
import json
from pathlib import Path


DATABASE_NAME = "iotguard-stage4.sqlite3"
MARKER_NAME = ".iotguard-stage4.json"


def validate_environment(environ):
    root = Path(environ.get("LINUXGUARD_INTEGRATION_RUNTIME", ""))
    if not root.is_absolute():
        raise RuntimeError("Collection mode requires an explicit absolute integration runtime")
    root = root.resolve()
    url = environ.get("LINUXGUARD_DATABASE_URL", "")
    if not url.startswith("sqlite:///") or Path(url[10:]).resolve() != root / DATABASE_NAME:
        raise RuntimeError("Collection mode may open only its marked integration SQLite database")
    if Path(environ.get("LINUXGUARD_DATA_DIR", "")).resolve() != root / "data":
        raise RuntimeError("Collection mode data directory must belong to the integration runtime")
    try:
        marker = json.loads((root / MARKER_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError("Use start_iot_integration.py to prepare a separate marked runtime") from exc
    if (marker.get("profile") != "collection_only" or marker.get("database") != DATABASE_NAME
            or marker.get("node_id") != environ.get("LINUXGUARD_COLLECTOR_NODE_ID")
            or environ.get("LINUXGUARD_DISCOVERY_CIDRS") != marker.get("target", "") + "/32"
            or (root / DATABASE_NAME).is_symlink()):
        raise RuntimeError("Integration runtime identity or target configuration does not match")
    return root
