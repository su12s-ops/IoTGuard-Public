# 训练文档与维护规范

2026-10-20 整理。历史训练/校准材料保留在 Git 历史；旧阶段的开关、验收数量和暂停指令属于当时实验上下文，不作为当前部署配置。当前唯一四角色架构不变，不新增第五个智能体。

## 可追溯来源

以下文件可在提交 `7cc1297b65fabfb490aaa694642e60d854d6e9ae` 中查看（后续 `1ff170a` 做过文档归档）：

| 历史文件 | 本轮沿用的约束 | 当前落点 |
|---|---|---|
| [IOT_UNIFIED_FOUR_AGENT_QUALITY_CLOSURE.md](https://github.com/su12s-ops/IoTGuard-Public/blob/7cc1297b65fabfb490aaa694642e60d854d6e9ae/IOT_UNIFIED_FOUR_AGENT_QUALITY_CLOSURE.md) | 原始失败留存；真实模型、规则兜底和模拟测试分开；证据不足不等于安全 | 注册证据、引用校验、独立 shadow 回归 |
| [IOT_UNIFIED_FOUR_AGENT_QUALITY_REPORT.md](https://github.com/su12s-ops/IoTGuard-Public/blob/7cc1297b65fabfb490aaa694642e60d854d6e9ae/IOT_UNIFIED_FOUR_AGENT_QUALITY_REPORT.md) | 分支、版本、backport、公告特异性分层；事实与推断分离 | evidence_prep 与漏洞分析员 |
| [IOTGUARD_STAGE10_WRITE_PERMISSION_CONTRACT.md](https://github.com/su12s-ops/IoTGuard-Public/blob/7cc1297b65fabfb490aaa694642e60d854d6e9ae/IOTGUARD_STAGE10_WRITE_PERMISSION_CONTRACT.md) | 控制/节点令牌与设备/实验写域互不授权；计划与身份绑定 | 持久 repair_domain、最终安装入口门禁 |
| [IOTGUARD_M5_MIGRATION_CONTRACT_V2.md](https://github.com/su12s-ops/IoTGuard-Public/blob/7cc1297b65fabfb490aaa694642e60d854d6e9ae/IOTGUARD_M5_MIGRATION_CONTRACT_V2.md) | 单一正式四角色管线；模型不可代签；治理事件追加留痕 | 现有 formal/shadow 管线 |
| [IOTGUARD_FINAL_PRODUCT_ACCEPTANCE_REPORT.md](https://github.com/su12s-ops/IoTGuard-Public/blob/7cc1297b65fabfb490aaa694642e60d854d6e9ae/IOTGUARD_FINAL_PRODUCT_ACCEPTANCE_REPORT.md) | 功能验收、运行时覆盖与业务接受分开 | 设备验收与本轮交付报告 |

查看命令（不会恢复或覆盖当前文件）：

```text
git show 7cc1297:IOT_UNIFIED_FOUR_AGENT_QUALITY_CLOSURE.md
git show 7cc1297:IOTGUARD_STAGE10_WRITE_PERMISSION_CONTRACT.md
```

## 当前维护要求

1. `supporting_evidence_ids` 只引用注册证据。CVE/GHSA/URL/哈希是来源属性，不能冒充证据 ID。IoT 公告导入生成 `ADV-IOT-*` 内容寻址记录；刷新公告不覆盖旧证据。
2. 引用校验失败先反馈一次原始报告与合法 ID；再次失败降级。不能删除引用后把无支持的结论算作成功。
3. `available/unavailable/error/stale` 是来源取得状态，不能当作 `released/not_affected/needed` 等发行版结论。
4. OpenWrt 资产初始域为 `unassigned`。控制端一次性登记 `production` 或 `openwrt_lab`，保存操作者与理由；清单、主机名、环境白名单不能替代或改写登记。旧审批缺少域绑定时不可继续安装，但只读续验保留。
5. 明文演示密码不再入库。旧密码必须显式迁移为专用环境变量引用后重新保存目标，旧凭据不会被静默用于运行。
6. 本轮硬件范围由操作员明确限定为 VMware/QEMU。签名更新是受信任宿主适配器，不得写成设备侧安全启动或实体断电恢复。
7. 测试锁定行为和安全边界；修复夹具必须说明缺少的前置事实，不能为通过测试放宽生产门禁。发布前记录全量、专项、现场和 CI 各自结果。

当前状态见 [项目状态](../status.md)；历史交付见 [交付报告](../archive/2026-10-20-delivery.md)、[权限规范](security-model.md)和[验证记录](../validation/testing.md)。
