# 测试结果

> 记录最近测试口径与结果，与 CI 保持一致。最后更新：2026-10-13

## 口径说明

- **常规回归（CI 口径）**：`python -m pytest -q --ignore=tests/test_iot_device_upgrade.py --ignore=tests/test_scan_runs.py --ignore=tests/test_scan_targets.py --ignore=tests/test_mqtt_remediation_workflow.py`（交付回归同口径；被排除的 4 个文件需要真实本机监听器 + 独立 profile，见 CURRENT_TASK 已知事项）
- **全量**：`python -m pytest -q`（在 conftest 审计钩子下，19 项真实套接字用例预期失败——历史已知，非回归）

## 最近结果（2026-10-13，Commit 6f4724b）

| 范围 | 结果 |
|---|---|
| 整改受影响 6 套件（stage3/stage12/stage4_collection/ebpf/agent_refactor/asset_parser） | 108 passed |
| 发现闭环专项（test_discovery_pipeline + test_discovery_identity_edge_cases） | 14 passed |
| 定向回归（iot_upgrade/scan_targets/api_smoke/stage12_ingestion/delivery_refactor） | 88 passed |
| 全量（参考） | 336 passed / 19 known-failed（真实套接字钩子冲突） |
| 前端构建（vite build） | 通过（829ms，仅既有 PURE 注释警告） |
| 真实发现闭环联调（live_discovery_check.py，SmartCam 模拟器 + 真实 API + 一次性库） | 16/16 PASS（两轮） |
| 合成样本导入器验证（parse_asset_document） | 通过 |

## 第六阶段真实联调（2026-10-13，reports/openwrt-live-* 本地留存）

| 项 | 结果 |
| --- | --- |
| OpenWrt 真实发现闭环（stage6_openwrt_live.py，16 验收点） | ALL PASS（含指纹比对/幂等/未授权拒绝/零写副作用） |
| 回归：discovery×2 + iot_upgrade + scan_targets + api_smoke + stage12 | 81 passed |
| SmartCam 真实闭环回归（live_discovery_check.py） | 16/16 PASS |
| CVE 分级 | 无公告→诚实零命中；无版本组件→延迟匹配（deferred） |

## 第六阶段主机线收尾（2026-10-13 晚，证据 reports/openwrt-hostline-* 本地留存）

| 项 | 结果 |
| --- | --- |
| Windows→Ubuntu SSH（显式 -i 专用密钥） | SSH_AUTH_SUCCESS（agent/config 零改动） |
| 真实 SSH 只读采集 ×2（复用采集任务管线） | 全部 completed：identity verified / auth succeeded / 182 包 / exit 0 |
| 同 request_id 复用 / 二采幂等 | 不重放 SSH；无重复建档（1 资产/1 连接/182 包） |
| 新旧清单 diff（vs 10-12 基线） | 181 一致 + 1 真实变化（kmod-nls-iso8859→-1） |
| 本轮快照 CVE 分级消费（隔离库） | 幂等；0 伪造结论；182 包全落"无充分证据"层 |
| 回归（discovery×2 + stage4_collection + iot_upgrade + api_smoke） | 76 passed |

## CI（.github/workflows/ci.yml）

- backend-job：Python 3.12 + 常规回归口径
- frontend-job：Node 20 + npm ci + vite build
