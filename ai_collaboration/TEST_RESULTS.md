# 测试结果

> 记录最近测试口径与结果，与 CI 保持一致。最后更新：2026-10-14

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

## 第七阶段 Zephyr 接入（2026-10-13）

| 项 | 结果 |
| --- | --- |
| 固件构建（Zephyr v4.4.2 / qemu_x86_64 / SDK v1.0.1 GNU） | 构建成功（5.7MB ELF + 28KB locore） |
| Zephyr Mock 测试（发现/身份/建档/CVE 三层/不合并/幂等/画像） | 5 passed |
| 回归（zephyr + discovery×2 + api_smoke） | 26 passed |
| QEMU 运行 | **阻塞**：SDK QEMU v10.0.2 与 locore 不兼容（无串口输出） |
| 真实端到端发现 | 待 QEMU 解决后执行 |

## 第七阶段真实端到端联调（2026-10-14，证据 reports/zephyr-live-20261014-085507/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 固件构建（qemu_cortex_a9 / arm-zephyr-eabi / 含 eth_xlnx_gem 网络栈） | 构建成功（2.33MB ELF，RAM 964KB） |
| QEMU 启动（系统 qemu-system-arm 8.2.2 / xilinx-zynq-a9 / cadence_gem） | 启动成功：Booting → dhcp ok → http on :80 |
| 真实网络（Windows → VMnet2 → Ubuntu SLIRP → 固件） | 跨主机 TCP/HTTP 可达，/api/system 实时可取 |
| 真实联调验收 stage7_zephyr_live.py | **20/20 ALL PASS**（预检/白名单画像/发现/身份建档 0.9/固件元数据/版本化组件/协议指纹/能力 unsupported/清洁库 CVE 诚实零/TEST-FIXTURE 三层/复扫幂等/未授权 400/零修复副作用/组件无重复） |
| 回归复跑（zephyr + discovery + identity_edge + api_smoke） | 26 passed |
| CVE 口径 | 清洁库零命中=无证据（非无漏洞）；三层分级用显式 TEST-FIXTURE（仅一次性临时库，与 live_discovery_check 同口径） |

## 第八阶段统一 Trace（2026-10-14，证据 reports/stage8-trace-20261014-094539/ 本地留存）

| 项 | 结果 |
| --- | --- |
| 专项 test_trace_system.py（四智能体完整 Trace/顺序/证据关联/并发隔离/失败呈现/审批拒绝/预算拦截/回滚前置/Zephyr unsupported/旧数据兼容/脱敏/分页统计/只读 not_requested/管线 Trace） | **15/15 passed** |
| 全量回归（python -m pytest -q） | 356 passed / 19 failed（19 全部落在既有已知冲突文件 test_iot_device_upgrade+test_mqtt_remediation_workflow+test_scan_runs；改动前基线同口径 33 failed——无新增回归，失败数为套件抖动） |
| 前端构建（vite build） | 通过 |
| 前端浏览器实测（构建产物 + 真实后端） | 四区域真实数据展示通过（截图本地留存） |
| 真实只读演示 stage8_trace_demo.py | **ALL PASS**（真实 DeepSeek LLM：4/4 智能体真实 token 用量；Zephyr 设备真实发现入档；Harness not_requested 诚实呈现） |

诚实性备注：LLM 用量仅记录响应真实携带的 usage（deepseek-v4-flash，prompt/completion/total tokens 真实）；剧本客户端与无密钥场景如实 unavailable。

## CI（.github/workflows/ci.yml）

- backend-job：Python 3.12 + 常规回归口径
- frontend-job：Node 20 + npm ci + vite build
