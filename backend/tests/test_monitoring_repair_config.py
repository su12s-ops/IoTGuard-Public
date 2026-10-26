"""Validate private service-environment updates without sudo, SSH or a device."""
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("repair_falco_service",
    Path(__file__).resolve().parents[2] / "scripts/repair_falco_service.py")
repair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repair)


def test_updates_only_requested_keys_and_keeps_original_configuration():
    original = '# Existing settings\nAPI_BASE=old\nASSET_ID=7\nOTHER="keep me"\n'
    output = repair.updated_environment(original, {"API_BASE": "http://127.0.0.1:18445/api", "ASSET_ID": "1"})
    assert '# Existing settings\n' in output and 'OTHER="keep me"\n' in output
    lines = [line for line in output.splitlines() if line.startswith("API_BASE=")]
    assert len(lines) == 1
    assert json.loads(lines[0].split("=", 1)[1]) == "http://127.0.0.1:18445/api"
    assert "ASSET_ID=7" not in output
    assert 'ASSET_ID="1"' in output


@pytest.mark.parametrize("value", ["token\nOTHER=injected", "token\rOTHER=injected", None])
def test_environment_values_cannot_inject_another_setting(value):
    with pytest.raises(ValueError, match="invalid environment"):
        repair.updated_environment("", {"LINUXGUARD_CONTROL_TOKEN": value})
