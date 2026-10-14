# LinuxGuard Falco 常驻采集部署手册（eBPF 2.0 P1-2 部署准备）

> 状态：**准备完成，未执行**。本目录全部内容为部署物；任何 `--apply`/`--install-service`/`--rollback`
> 或 `systemctl start` 均需在 **VM sudo 授权窗口**内由运维确认后执行。
> 本轮（P1 准备）未在 VM 或任何主机执行特权操作。

## 1. 版本与兼容性要求

| 项 | 要求 | 依据 |
|---|---|---|
| Falco | ≥ 0.37（实测目标：Ubuntu VM falco 0.44.1 / Libs 0.25.4，审计轮安装实测） | `falco --version` |
| 规则语法 | 现代字段名（proc.*、fd.*、evt.*），`rules.d/` 目录加载 | `collector/linuxguard_iot_rules.yaml` |
| python3 | ≥ 3.8（转发器批量/重试/spool，P0 已验收） | `collector/ebpf_event_collector.py` |
| 后端 | LinuxGuard FastAPI ≥ P0（批量端点 `/runtime/ebpf/events/batch`） | P0 报告 |

## 2. 所需内核能力

- **首选路线（modern eBPF / CO-RE）**：`/sys/kernel/btf/vmlinux` 存在（BTF）。
  无需内核模块、无需改内核参数——只读 syscall 观测。
- **BTF 缺失时**：falco 回退 kmod/legacy 路线需要加载内核模块——**超出本轮授权**，
  明确不做；`--check` 会如实报告 BTF 状态。
- **LSM/enforce**：与本部署无关；项目边界保持 observe-only（审计报告 §2.1）。

## 3. 运行权限

- 加载 eBPF 探针需 **root**（systemd 单元不降权）。
- 规则目录写入：root（`/etc/falco/rules.d/`，0644）。
- 状态目录：`/var/lib/linuxguard/falco/`（spool、stderr、健康文件）。
- 网络：仅出站访问后端 API（默认 `http://<后端>:8000/api`）；无入站监听。
- 凭据：`LINUXGUARD_CONTROL_TOKEN` 等经 `/etc/linuxguard/falco.env` 注入，
  **不写入源码与本仓库**。

## 4. 部署步骤（需授权窗口）

```bash
# 0) 只读体检（任何时候可跑，无需 root）
./deploy_falco.sh --check

# 1) 部署自定义规则（自动备份原文件 → /var/lib/linuxguard/falco-deploy-backups/）
sudo ./deploy_falco.sh --apply

# 2) 安装常驻单元（不启动；ExecStartPre 会与 falco-modern-bpf 互斥协调）
sudo ./deploy_falco.sh --install-service

# 3) 配置环境（资产 ID、令牌、后端地址）
sudo install -m 0600 /dev/null /etc/linuxguard/falco.env
sudo sh -c 'cat > /etc/linuxguard/falco.env <<EOF
API_BASE=http://<后端>:8000/api
ASSET_ID=<已注册资产ID>
LINUXGUARD_CONTROL_TOKEN=<令牌>
EOF'
```

部署物就位路径：单元假设仓库位于 `/opt/linuxguard/`（否则改 `ExecStart` 路径）。

## 5. 启动与停止流程（需授权窗口）

```bash
sudo systemctl start linuxguard-falco      # 启动（先停 falco-modern-bpf，Conflicts+ExecStartPre）
journalctl -u linuxguard-falco -f          # 观察 falco stderr 与转发器日志
sudo systemctl stop linuxguard-falco       # 停止（SIGTERM；转发器发 stopped 心跳并保留 spool）
```

停止语义：未确认批次留在 spool（未确认≠丢失），下次启动先续传（P0 语义）。
验收基线：常驻 ≥10 分钟，期间制造真实行为（见 §7），服务端收到对应事件。

## 6. 失败回滚方案

```bash
sudo ./deploy_falco.sh --rollback
```

- 规则：按最近备份还原；部署前无该文件则移除新增文件。
- 单元：停止 linuxguard-falco、按备份还原或移除、daemon-reload。
- 发行版 falco 服务：`Conflicts` 保证互斥；是否恢复 `falco-modern-bpf`
  由运维按基线决定（回滚脚本不擅自启动其他服务）。
- 数据：spool 与后端数据不受回滚影响（证据层只追加）。

## 7. 真实事件验证方案（部署后执行）

1. `--check` 全绿（falco/BTF/规则/forwarder 依赖）。
2. 启动常驻服务，等待 ≥30s（心跳注册传感器）。
3. 在目标机触发真实行为链（服务→shell→下载器）：
   `sudo sh -c 'cat /etc/shadow'`、`curl -s http://127.0.0.1/`、
   `mosquitto_pub`/`wget`（按资产角色选择）。
4. 后端验证：`GET /runtime/ebpf/events?limit=…` 出现 source=falco 的事件；
   `GET /runtime/ebpf/reliability` 的 `server_observed.stored_events` 增长；
   自定义规则（`LG-IoT …`）优先于默认规则命中。
5. 链式验收：`LinuxGuard IoT Service Spawned Shell` / `Shell Run Downloader`
   规则对真实 `mosquitto → sh → wget` 链产生 WARNING 事件（P1-2 验收方法）。

## 8. 真实丢失计数：获取与不可用判定

- **来源**：falco stderr 结构化 stats（`"drops":<N>` 字段族）。
  `run_standing_capture.sh` 的 supervisor 循环每 15s 解析一次
  `${STATE_DIR}/falco.err` → 健康文件 `falco-probe-health.json`。
- **语义（与 P0 一致）**：解析到数值 → `dropped_events=N`（0=真实零）；
  从未解析到 → `null` → 转发器心跳/`GET /runtime/ebpf/reliability` 呈现
  `unavailable`，**绝不虚构为零**。
- **待真实验证项**：目标 falco 0.44.1 的 stderr stats 输出格式与频率
  （`-o log_level=info` 下是否周期输出 stats 行）需在 VM 授权窗口实测确认；
  若格式不符，仅调整解析正则，语义不变。

## 与 bpftrace 路线的关系

两路线并行、语义一致（进程/网络/文件），后端 `normalize_event` 统一归一化；
bpftrace 路线本轮已完成 P1-1 增强（argv/start_time/会话键，见
`IOT_EBPF2_P1_PREP_REPORT.md`）。Falco 路线的 argv（`proc.cmdline`）为引擎
原生能力，无需探针改动。
