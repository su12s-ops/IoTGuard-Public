# 最近一次开发结果

> 每完成一个任务归档摘要并同步至 Public。最后更新：2026-10-13

## 2026-10-13：第六阶段 OpenWrt 真实接入（设备线全通，主机线受阻待凭据）

- 真实环境：复用 VMnet2 实验段中运行中的 OpenWrt 25.12.5 x86/64 VM；TCP 22/80/443/53 全部可达
- 主机指纹：仅握手（不认证）取证 SSH ed25519 指纹，与第四阶段首次采集的受信记录完全一致
- 发现闭环：标准模式后端（一次性临时库，白名单=授权实验段）经真实 HTTP API 双 /25 扫描；
  OpenWrt 以横幅证据建档（dropbear/http/https 真实指纹，identity=banner_heuristic，无伪造身份）；
  同段另发现 Ubuntu 第二网卡 ssh 服务（属授权段内真实事实）
- CVE 分级：dropbear 横幅不含版本 token → 无版本组件证据 → 按规则延迟匹配；
  未登记公告 → 零命中=无证据（非无漏洞）；全程未提升候选为确认
- 幂等/边界：复扫 enrolled_new=0；未授权网段 400；harness/remediation 全零
- 阻塞：Windows→Ubuntu SSH publickey 仍被拒 → 主机线 SSH 只读采集与 match_openwrt 精确匹配待凭据恢复；
  按项目策略不从 Windows 执行设备采集（stage6 脚本不含任何私钥加载）
- 新增：backend/scripts/stage6_openwrt_live.py（可重复的真实联调入口，16 个验收点）
- 回归：后端 6 套件 81 项 + SmartCam 真实闭环 16/16 全过

## 2026-10-13：公开前安全整改 + 托管机制建设

### 安全整改（Private Commit 6f4724b，已推送）

- 删除无引用截图 `frontend/public/fix-nginx.png`（含真实用户名提示符）
- 5 个文件旧竞赛工程绝对路径 → 中性占位符/根目录推导（`collector/run_real_capture_once.sh` 改为脚本位置推导 PROJECT_ROOT）
- eBPF 采集夹具真实主机名 → `lab-ebpf-host`（40 行，语义不变）
- 两个资产样本文件（根目录 sample + tests/fixtures structure sample）替换为全合成数据，经真实导入器 `parse_asset_document` 验证兼容
- 3 个阶段文档中 `C:\Users\<user>` 占位符化（6 处）
- 回归：后端受影响 6 套件 108 项全过；前端构建通过；业务零变更

### 托管机制（本轮新增）

- `ai_collaboration/` 5 份协作文件
- `.github/`：Issue×2 / PR 模板 + CI 工作流（后端 pytest 交付口径 + 前端构建）
- `scripts/sync_public.py`：Private→Public 单向同步（导出跟踪树 → 敏感扫描 → 增量提交 → 推送，来源 hash 写入 commit message）
- Public 仓库 `su12s-ops/IoTGuard-Public` 建立独立历史并完成首次同步

### 历史安全基线

Private 初始提交 a05f3c8 含整改前标识（真实主机名×40 等）——按授权保持不重写；**Public 不含该历史**。当前 HEAD 工作区经多维扫描：凭据 0、真实环境标识 0、二进制文件 0。
