"""OpenWrt lab-clone write-scope contract: fail-closed, mutually exclusive
with the production master switch, per-asset exact declaration."""
import json
from types import SimpleNamespace

import pytest

from app.services import agent_harness as h


def _monkey_env(monkeypatch, **kwargs):
    for key, value in kwargs.items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)


def test_scope_unset_rejects_everything(monkeypatch):
    _monkey_env(monkeypatch, LINUXGUARD_ENABLE_OPENWRT_LAB_REPAIR=None,
                LINUXGUARD_OPENWRT_LAB_ASSET_SCOPE=None)
    assert h.openwrt_lab_write_state(9) == (False, "openwrt_lab_repair_disabled")


def test_scope_enabled_but_undeclared_asset_rejected(monkeypatch):
    _monkey_env(monkeypatch, LINUXGUARD_ENABLE_OPENWRT_LAB_REPAIR="1",
                LINUXGUARD_OPENWRT_LAB_ASSET_SCOPE="12")
    assert h.openwrt_lab_write_state(2) == (False, "openwrt_lab_asset_scope_not_declared")
    assert h.openwrt_lab_write_state("2")[0] is False


def test_scope_declared_asset_allowed(monkeypatch):
    _monkey_env(monkeypatch, LINUXGUARD_ENABLE_OPENWRT_LAB_REPAIR="1",
                LINUXGUARD_OPENWRT_LAB_ASSET_SCOPE=" 12 , 13 ")
    assert h.openwrt_lab_write_state(12) == (True, "")
    assert h.openwrt_lab_write_state(13)[0] is True


def test_production_master_switch_does_not_grant_lab_scope(monkeypatch):
    """Turning on the production master must not satisfy the lab contract."""
    _monkey_env(monkeypatch, LINUXGUARD_ENABLE_DEVICE_REPAIR="1",
                LINUXGUARD_ENABLE_OPENWRT_LAB_REPAIR=None,
                LINUXGUARD_OPENWRT_LAB_ASSET_SCOPE=None)
    assert h.openwrt_lab_write_state(12)[0] is False


def test_lab_scope_does_not_enable_out_of_scope_writes(monkeypatch, tmp_path):
    """install_registered_package must fail closed for any asset outside scope."""
    _monkey_env(monkeypatch, LINUXGUARD_ENABLE_DEVICE_REPAIR=None,
                LINUXGUARD_ENABLE_OPENWRT_LAB_REPAIR="1",
                LINUXGUARD_OPENWRT_LAB_ASSET_SCOPE="12")
    artifact = tmp_path / "pkg.apk"
    artifact.write_bytes(b"LAB TEST ONLY")
    item = {"sha256": "0" * 64, "package_manager": "apk"}
    connection = SimpleNamespace(asset_id=2)
    with pytest.raises(ValueError, match="设备写操作未启用"):
        h.install_registered_package(connection, item, artifact)
