# Pull Request

## 变更说明

<!-- 做了什么、为什么；关联 Issue（#N） -->

## 涉及模块

- [ ] backend（routers / services / models / migrations）
- [ ] frontend
- [ ] collector / simulator
- [ ] 脚本 / CI / 文档

## 测试

- [ ] 常规回归（CI 口径：`pytest -q --ignore=tests/test_iot_device_upgrade.py --ignore=tests/test_scan_runs.py --ignore=tests/test_scan_targets.py --ignore=tests/test_mqtt_remediation_workflow.py`）
- [ ] 本次变更的专项测试（列名）

## 安全检查单

- [ ] 未引入真实凭据/Token/私钥/未脱敏环境标识
- [ ] 未触碰 backend/.env、backend/data/、reports/、asset_inventory.json
- [ ] 未扩大授权网段、未开启自动修复
- [ ] 数据库变更为兼容性增量迁移（如有）
