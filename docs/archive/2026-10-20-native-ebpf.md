# eBPF C 核心重写与验收（2026-10-20）

> 历史记录：保留当时的结果、失败与限制，不代表当前部署状态。当前入口见 [项目状态](../status.md)。

已实现原生 C CO-RE 探针和 libbpf 加载器，并完成隔离环境的真实内核、转发与后端验证。当前生产采集服务未切换；这些结果不代表长期运行或所有内核版本的稳定性保证。

## 四项修复

| 问题 | 当前实现 |
|---|---|
| 生命周期分散、健康状态可能失真 | supervisor 统一管理 C 采集器与转发器；加载并挂载成功后才报告运行；单实例锁、原子健康文件、优雅退出、异常联动失败；systemd 重启整个单元 |
| 操作与结果语义不准确 | syscall 入口/出口关联；exec 成功从 sched 确认；open 只表示打开，不推断实际读写；connect 明确 success/failure/pending；返回值和 errno 贯穿证据 API 与界面；进程实例与 exec 代次分离 |
| 端到端可靠性不足 | 内核丢失、读取失败、映射失败及用户态输出分别计数；有界内存和输出背压；复用持久化 WAL；完整 ACK 校验与幂等重放；队列满返回 503，转发器保留 WAL |
| 接收与证据处理耦合 | 原生事件和持久化证据任务同事务提交；后台 worker 重试与恢复；证据写入和任务删除同事务；API 明确 ACK 是持久化确认，并暴露待处理数量 |

```mermaid
flowchart LR
    K[C CO-RE 内核探针] --> R[有界 Ring Buffer]
    R --> C[C libbpf 加载器]
    C --> W[Python WAL 转发器]
    W --> A[FastAPI 接收]
    A --> D[(事件与证据任务同事务)]
    D --> E[后台证据 worker]
    E --> S[(安全证据)]
    S --> U[分析与界面]
```

C 重写范围是内核探针、加载、事件输出和健康计量。HTTP/WAL 与业务分析继续使用已有 Python 实现。没有进行与旧实现等负载的性能对比，因此不宣称特定加速比例。

## 实际验证

环境：x86-64 WSL2 Linux 6.6.87.2、clang 18、libbpf 1.3。

- C 构建通过，使用 `-Wall -Wextra -Werror`；前端构建通过。
- 真实内核持续运行 180 秒：889 轮、8176 条事件；观察、发出、用户态接收和输出均为 8176；ring/map/output/ABI 错误为 0，unmatched 为 0；RSS 首尾和峰值均为 35636 KB。
- 上述运行有 **1 次 read_errors**，已如实保留；事件数量对齐不代表所有字段均读取成功。
- 覆盖打开成功/失败、exec 失败与执行代次、连接成功/拒绝/pending、JSON 转义、单实例、停止、重启与断管失败。
- 最终真实采集器到生产转发器复验：937 条事件被隔离 HTTP 接收端接受；断网期间 WAL 保留 5500 字节；恢复连接、优雅排空、采集器 SIGKILL 导致单元失败、重新启动均通过。
- 93 条新鲜 C 事件另经隔离的真实 FastAPI、SQLite 和 lifespan worker 验证，生成 93 条证据；重放识别 93 条重复。
- 最终核心/运行时回归：69 passed；eBPF 兼容性、WAL、证据和归档恢复回归：131 passed。两组有重叠，不应相加作为独立用例数。仅有测试中 `datetime.utcnow()` 弃用警告。

本地原始报告位于 `reports/native-ebpf-20261020/`（忽略目录，不随 Git 提交）：`iotguard-native-verification.json`、`transport-final.json`、`ingest.json`。新增 CI 工作流，但本次未在远程 GitHub Runner 上执行。

## 部署与边界

构建、服务配置、回退和复验命令见 [原生采集器说明](../../collector/native/README.md)。服务模板为 `deploy/linux/iotguard-ebpf.service`，配置示例为 `deploy/linux/ebpf.env.example`。须在实际 Linux 采集节点构建并使用真实资产及凭据配置；当前仅完成隔离验证。

当前是观察框架，不是 LSM 阻断器。覆盖 execve、成功 execveat、openat 和 connect 系统调用；未覆盖失败 execveat、openat2、实际 read/write/mmap 和异步连接最终状态。路径/参数有界截断，非规范化路径和读取不可用均保留边界信息。

持久化保证始于 WAL append；内核过载、进程被强杀和采集器挂载前后的窗口不能承诺零丢失。原生证据最终一致；SQLite 使用单后端 worker，监控任务积压及磁盘空间。跨内核、多架构、生产负载和长时间耐久运行仍需在目标部署环境验证。
