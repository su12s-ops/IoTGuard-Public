# 技术架构

IoTGuard 以设备发现、证据化漏洞判断和设备适用修复为业务主线；四智能体、运行时传感器与 Harness 为支撑。默认工作台 `/`，SOC `/soc`。实现边界见 [产品状态](docs/STATUS.md)。

## 控制面

Vue 3 前端通过 FastAPI 路由访问业务服务；SQLAlchemy / SQLite 保存设备、组件、漏洞、风险、任务与证据。后端启动时完成建表及增量迁移，运行数据保存在独立数据目录。

## 分析面

LangGraph 四角色为资产调查、漏洞分析、运行时分析和决策规划。正式入口 `/api/analysis`，正式写入器 `unified.adapter.formal_sink`。模型输出经过证据与治理门禁，操作员裁定独立留痕。只读补证经授权后进入原始清单与同一正式再研判路径。

## 执行面

Harness 使用计划哈希、连接签名、Collector 摘要、资产锁、预算与产物注册表约束任务。外部 Linux Pull Runner 领取已排队任务，经 SSH 指纹钉扎执行固定采集脚本并回传原文。OpenWrt logread 周期拉取、保留 boot_id 与原始时间、幂等去重；不是 eBPF，也不能证明零丢失。

设备写入采用双轨开关：生产总开关 `LINUXGUARD_ENABLE_DEVICE_REPAIR` 与隔离实验作用域（Ubuntu `LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR` + 精确资产声明、OpenWrt `LINUXGUARD_ENABLE_OPENWRT_LAB_REPAIR` + `LINUXGUARD_OPENWRT_LAB_ASSET_SCOPE`）互不替代、双向 fail-closed；实验授权无法通过打开生产开关获得，反之亦然。

## 实验隔离（OpenWrt-Lab）

原机 OpenWrt-01 保持生产对照组；独立克隆 OpenWrt-Lab 经冻结快照基盘复制创建，在首次联网前完成 hostname、dropbear 主机密钥、静态 MAC、管理网段与凭据的离线身份隔离（WSL2 loop 只读写 rootfs），S0-CLEAN 基准快照通过无害标记真实恢复测试。克隆以独立资产/连接/专用采集密钥接入产品，采集、匹配与风险和原机完全分离。

## 证据与追踪

资产清单、官方公告原文哈希、运行时 SecurityEvidence、TraceRun / TraceEvent、智能体与工具审计关联同一设备和任务。证据或原文可能早于最终任务回执提交，崩溃重试依赖幂等，不宣称跨表原子事务。

## 部署边界

Compose 启动非 root API 与 nginx；数据使用命名卷。采集节点、Falco 与设备凭据在外部 Linux 主机。Zephyr QEMU HTTP 身份由后端读取，不具备 SSH、包管理或 eBPF。QEMU 宿主固件切换不等于签名 OTA。

身份、写开关、人审与独立实验权限见 [权限规范](docs/SECURITY_MODEL.md)，环境模板见 [重建指南](deploy/README.md)。
