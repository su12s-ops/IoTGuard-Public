# 协作四：治理与人工签署

- 标准部署三个写开关均为 0；OpenWrt `repair_domain=unassigned` 默认拒绝写入。
- 凭据只保存环境变量引用，旧明文阻止运行；节点令牌、资产身份和采集权限分离绑定。
- 模型建议、机器验证、代理执行和人工签署分别记录；`business_accepted=false` 不得被自动改写。
- CVE-2026-62948 与 Mimosa `partial/inconclusive` 继续独立开放。
