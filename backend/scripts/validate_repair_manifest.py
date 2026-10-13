"""Validate all local repair artifacts without connecting to any device."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import config  # noqa: E402,F401 - load the local environment configuration
from app.services.agent_harness import artifact_registry, load_artifact  # noqa: E402


def main():
    try:
        registry, _ = artifact_registry()
        if not registry:
            print("No repair artifacts registered. Investigation remains available.")
            return 1
        for artifact_id in registry:
            item, _, _ = load_artifact(artifact_id)
            print("OK: " + artifact_id + " / " + item["package_name"] + " / " + item["version"])
        print("File integrity checks passed. Device applicability is checked when creating a plan.")
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print("Manifest validation failed: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
