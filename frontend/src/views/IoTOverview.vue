<template>
  <section class="page" v-loading="loading">
    <header class="page-header">
      <div><span class="eyebrow">IOTGUARD</span><h1>物联网安全工作台</h1>
        <p>从设备接入、漏洞识别到证据研判与受控修复，按设备追踪安全业务。</p></div>
      <div class="header-actions"><el-button @click="load">刷新</el-button><el-button type="primary" @click="router.push('/iot')">接入设备</el-button></div>
    </header>
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" role="alert" />
    <section class="metric-strip compact-metrics" aria-label="设备安全概况">
      <article><span>物联网设备记录</span><strong>{{ data.device_count }}</strong></article>
      <article><span>待评估设备</span><strong>{{ data.devices.filter(d => d.matches.assessment === 'unassessed').length }}</strong></article>
      <article><span>已确认漏洞记录</span><strong>{{ data.devices.reduce((n, d) => n + d.matches.confirmed, 0) }}</strong></article>
      <article><span>待核验候选记录</span><strong>{{ data.devices.reduce((n, d) => n + d.matches.pending, 0) }}</strong></article>
    </section>
    <section class="operation-section"><h2>设备安全闭环</h2>
      <p>未匹配不代表安全；公告快照数量不代表适用性已完成。不同台账记录保留原始身份，不按 IP 自动合并。</p>
      <DataTable :rows="data.devices">
        <el-table-column prop="name" label="设备" min-width="170" />
        <el-table-column prop="ecosystem" label="设备类型" min-width="110" />
        <el-table-column prop="version" label="系统 / 固件" min-width="170" />
        <el-table-column label="漏洞识别" min-width="180"><template #default="{ row }">{{ row.matches.assessment === 'unassessed' ? '尚未评估' : '部分评估' }} · {{ row.matches.confirmed }} 已确认 / {{ row.matches.pending }} 待核验</template></el-table-column>
        <el-table-column label="运行时证据" min-width="170"><template #default="{ row }">{{ row.runtime === 'ebpf_not_applicable' ? 'RTOS 不支持 eBPF，需设备侧证据' : '需核验关联传感器及证据新鲜度' }}</template></el-table-column>
        <el-table-column label="修复能力" min-width="170"><template #default="{ row }">{{ row.remediation === 'firmware_update_not_automated' ? '固件自动更新尚未接通' : '需设备专用方案与授权' }}</template></el-table-column>
        <el-table-column label="下一步" min-width="190"><template #default="{ row }"><el-button size="small" @click="router.push(row.detail_path)">检查设备与漏洞</el-button><el-button size="small" @click="router.push(row.task_path)">研判任务</el-button></template></el-table-column>
      </DataTable>
      <el-empty v-if="!loading && !data.devices.length && !error" description="尚无物联网设备记录，请接入 OpenWrt 或发现受支持设备" />
    </section>
    <section class="operation-section"><h2>官方情报与支撑设施</h2>
      <p>OpenWrt 公告快照 {{ data.official_snapshot_counts.openwrt }} 条；Zephyr {{ data.official_snapshot_counts.zephyr }} 条。Ubuntu 等主机记录 {{ data.infrastructure_count }} 条，作为采集、控制面或对照设施管理。</p>
      <el-button @click="router.push('/workflow')">多智能体风险研判</el-button><el-button @click="router.push('/remediation')">授权修复与验证</el-button><el-button @click="router.push('/soc')">SOC 安全总览</el-button>
    </section>
  </section>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import { api } from '../api';
import DataTable from '../components/DataTable.vue';
const router = useRouter();
const loading = ref(false);
const error = ref('');
const data = ref({ devices: [], device_count: 0, infrastructure_count: 0, official_snapshot_counts: { openwrt: 0, zephyr: 0 } });
async function load() {
  loading.value = true;
  error.value = '';
  try { data.value = (await api.get('/devices/business/overview')).data; }
  catch (e) { error.value = e.response?.data?.detail || '设备业务概况加载失败，请重试'; }
  finally { loading.value = false; }
}
onMounted(load);
</script>
