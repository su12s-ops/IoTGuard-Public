# 本地生产控制台与质量复验

新增入口用于本机隔离验证，不读取操作员 `.env`，不覆盖现有设备库，也不自动生成漏洞或模型结果。

## 构建与启动

需要 Python 3.12+、Node.js 24。建议独立虚拟环境。

```powershell
python -m venv reports/runtime-venv
reports/runtime-venv/Scripts/python -m pip install -r backend/requirements.txt -r backend/requirements-test.txt
npm --prefix frontend ci
npm --prefix frontend run build
reports/runtime-venv/Scripts/python scripts/serve_local.py --port 18100
```

打开 <http://127.0.0.1:18100>。前端生产默认使用同源 `/api`，开发模式仍默认 localhost:8000；显式 `VITE_API_BASE` 配置优先。

- 默认数据库、归档与操作令牌位于被 Git 忽略的 `reports/local-runtime`。已有正式数据库不受影响。
- 操作令牌保存在该目录的 `control-token.txt`；不要公开、提交或截图令牌。
- 三个设备修复开关、启动清理和 OpenWrt 周期采集均关闭。重启保留数据。
- 模型仅在进程环境中显式配置时可用。空情报、无模型、无传感器必须如实显示，不等同安全。
- 默认仅监听 127.0.0.1；不要把此隔离验证入口直接暴露为生产服务。

## 复验

```powershell
python -m pytest -q
npm --prefix frontend run build
$env:PLAYWRIGHT_CHANNEL='msedge'
npm --prefix frontend run test:e2e
node scripts/smoke_browser.cjs http://127.0.0.1:18100 reports/browser-check-new
```

浏览器冒烟不拦截 API，检查六页面、脚本异常、真实 API 返回和跨源请求；配置提示与运行错误分别记录。

下面的 HTTP 检查会导入样例并归档/重置衍生数据，**只能用于可丢弃的隔离实例**，不得指向真实业务库：

```powershell
python scripts/smoke_local_runtime.py --base http://127.0.0.1:18100 --token-file reports/local-runtime/control-token.txt --output reports/http-check-new.json --allow-reset
```

检查结果采用独占创建，不覆盖历史证据。样例设备不是现场设备证据。测试成功不代表真实模型准确率、设备漏洞适用性、实体 OTA、24 小时稳定性或人工业务签收通过。

## Docker 真实采集接线

Docker API 虽然运行在 Linux，也不能在容器里保存设备私钥或冒充采集节点。使用外部 Linux pull runner 时，在本地 Docker 环境配置中显式设置：

```dotenv
LINUXGUARD_COLLECTION_EXECUTION_MODE=pull
```

`auto`（默认）保留原平台路由；`pull` 要求已登记执行节点，缺失时失败，不回退到容器 SSH；`local` 仅供具有合法本地采集环境的 Linux 后端使用。连接 preflight 与执行采用同一模式。预检成功只证明元数据条件满足，仍须核对本轮 collection-run 的终态、身份审计、清单哈希及采集时间。

固定采集脚本在当前 Docker 包布局下解析到 `/collector`，镜像必须复制到该路径。服务重建后，检查 `collector_available=true`，不能仅确认源码树存在脚本。

真实端到端顺序为：启动虚拟机及服务 → 核验登记身份和精确授权目标 → 本轮清单采集 → 本轮运行时日志采集 → 官方情报同步与匹配 → 确定性风险 → 正式四智能体批次 → 核验终态与人工复核缺口。`queued_remote`、模型启动回包、图运行 `completed` 均不能单独证明整轮通过；`human_review` 是需要人工处理的研判终态，不应伪装成设备安全。

本轮现场证据与范围记录见本地 `reports/e2e-20261023-094602/PROGRESS.md`。其中备份数据库和环境配置含敏感信息，仅留本机，不应发布或提交。

## 失败批次与重试边界

模型接口中断后，图仍会以每个角色 `APIConnectionError` 降级跑完并落到 `human_review`。这类批次的 `llm_calls=0`、`usage=null`，只能证明编排走完，不能当作一次有效研判，也不得据此评价模型质量。

重试必须走正式接口，不能直接改库：

```powershell
POST /api/analysis/risks/{risk_id}/human-review
{"decision":"request_reanalysis","reason":"...","actor":"...","expected_status":"pending_human_review"}
```

该调用把对象置回 `reanalysis_required` 并写入 `reanalysis_request` 治理事件，原报告、trace 与失败原因全部保留。之后用 `POST /api/analysis/runs?asset_id=..&risk_id=..&batch_size=1` 定向重跑，并在启动回包里核对 `selected_object_ids` 恰为预期对象。

任一角色角色级预算耗尽、决策接口超时、协作续轮失败都会让最终策略落到 `pending_human_review`，`final_score`/`final_level` 为空。预算、超时、校验与重试阈值不得为了让批次"通过"而临时放宽；`role_budgets_exhausted` 会单独列出触限角色，与 run 级预算耗尽区分。

