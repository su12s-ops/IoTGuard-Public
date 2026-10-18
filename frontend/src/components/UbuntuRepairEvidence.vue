<template>
  <section v-if="run?.plan?.adapter === 'ubuntu-apt-v1'" aria-label="Ubuntu 修复与复检证据">
    <h3>Ubuntu 修复与复检证据</h3>
    <p>资产 {{ run.asset_id }} · {{ run.plan.identity.hostname }} · {{ run.plan.identity.release }} / noble · 节点 {{ run.plan.node_id }}</p>
    <p><a v-for="notice in run.plan.official.notices" :key="notice" :href="'https://ubuntu.com/security/notices/' + notice" target="_blank" rel="noopener noreferrer">{{ notice }} </a> · <a :href="run.plan.official.url" target="_blank" rel="noopener noreferrer">官方 CVE 原文</a> · {{ run.plan.official.evidence_id }} · Trace {{ run.trace_id }}</p>
    <p>审批：{{ approvalLabel(run) }} · 预演：{{ run.plan.preflight ? (run.plan.preflight.ready ? '通过' : '未通过') : '尚未运行' }} · 实际执行：{{ executionLabel(run.result?.execution_status) }}</p>
    <p v-if="run.plan.preflight">软件包检查：{{ readinessLabel(run.plan.preflight.package_ready) }} · 节点管理员权限：{{ privilegeLabel(run.plan.preflight.execution_context) }}</p>
    <p v-if="run.plan.preflight?.issues?.length">阻止原因：{{ run.plan.preflight.issues.map(issueLabel).join('；') }}</p>
    <table class="data-table"><thead><tr><th>源包 / 已安装二进制</th><th>执行前版本</th><th>仓库候选版本</th><th>USN 修复目标</th><th>复检新版本</th></tr></thead>
      <tbody><tr v-for="p in run.plan.targets" :key="p.binary"><td>{{ p.source }} / {{ p.binary }}</td><td>{{ p.version }}</td><td>{{ run.plan.preflight?.candidate_versions?.[p.binary] || '待重新读取' }}</td><td>{{ run.plan.official.fixed_version }}</td><td>{{ run.result?.verification?.after?.find(a => a.binary === p.binary)?.version || '尚无修复后采集' }}</td></tr></tbody>
    </table>
    <p>复检结论：{{ run.result?.verification?.status || '未执行修复后复检' }} · 风险更新建议：{{ run.result?.verification?.risk_update_recommendation || '保持原风险' }}</p>
    <p>回滚：{{ rollbackLabel(run.result?.rollback?.status || run.plan.rollback.status) }} · 隔离快照恢复须单独批准；原始风险和旧研判只读保留。</p>
    <p v-if="run.result?.verification">新证据：{{ run.result.verification.inventory_evidence_id }} · SHA256 {{ run.result.verification.inventory_sha256 }}</p>
    <el-collapse v-if="run.plan.preflight"><el-collapse-item title="软件包与依赖变化预演"><pre class="upgrade-json">{{ run.plan.preflight.simulation }}</pre><p>移除包：{{ run.plan.preflight.removals?.length || 0 }}；未刷新 apt 索引。{{ run.plan.preflight.rollback?.snapshot_restore }}</p></el-collapse-item></el-collapse>
    <p>漏洞修复仅为 curl 同源包维护；采集器健康恢复、日志备份分别处理，Falco 重启不属于漏洞修复。</p>
  </section>
</template>
<script setup>
const approvalLabel = run => ({cancelled: '计划已取消', invalidated: '计划已失效'}[run.status] || run.approved_by || (run.plan.preflight && !run.plan.preflight.ready ? '预演未通过，审批关闭' : '待独立人工审批'));
const executionLabel = value => ({not_executed: '尚未执行', queued: '已排队，尚未确认执行', command_succeeded: '软件包命令成功，仍须依据复检', package_operation_failed: '软件包操作失败', unknown_or_interrupted: '执行中断或结果未知'}[value] || value || '尚未执行');
const rollbackLabel = value => ({awaiting_clone_and_restore_test: '待隔离副本与快照恢复验证', restore_verified_by_operator_attestation: '已登记人工恢复验证凭据，尚未恢复'}[value] || value);
const readinessLabel = value => value === true ? '通过' : value === false ? '未通过' : '未单独验证';
const privilegeLabel = context => Number.isInteger(context?.effective_uid) ? (context.effective_uid === 0 ? '已验证' : '缺少管理员权限') : '未验证，须重新预演';
const issueLabel = value => {
  const code = value.split(':')[0];
  const label = {official_candidate_unavailable: '本机仓库索引无适用的官方修复候选', candidate_checksum_unavailable: '无法取得目标包校验摘要', candidate_source_mismatch: '目标版本源包元数据缺失或不一致', dependency_scope_rejected: '依赖预演失败或超出批准范围', held_package: '目标包已锁定', dpkg_incomplete: '存在未完成的软件包事务', insufficient_disk_space: '磁盘空间不足', root_execution_node_required: '节点尚未证明具备管理员执行权限，请配置后重新预演'}[code];
  return label ? `${label}（${value}）` : value;
};
defineProps({ run: { type: Object, default: null } });
</script>
