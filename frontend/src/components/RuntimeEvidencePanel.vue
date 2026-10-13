<template>
  <section class="operation-section upgrade-page" aria-label="运行时证据时间线" v-loading="loading">
    <div class="section-head"><div><h2>进程时间线与采集覆盖</h2><p>按可靠进程身份关联同一资产的事件；关联结果不代表已确认漏洞利用。</p></div></div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <el-form label-position="top" class="upgrade-form-grid"><el-form-item label="查看资产"><el-select v-model="assetId" aria-label="时间线资产" @change="loadTimeline"><el-option v-for="a in assets" :key="a.id" :value="a.id" :label="a.hostname" /></el-select></el-form-item><el-form-item label="修复对比时间点"><el-date-picker v-model="checkpoint" type="datetime" aria-label="修复对比时间点" /></el-form-item><el-form-item label="对比窗口"><el-button :disabled="!assetId || !checkpoint" :loading="comparing" @click="compare">比较前后各五分钟</el-button></el-form-item></el-form>
    <template v-if="timeline"><p class="operation-help">采集状态：{{ coverageLabel(timeline.coverage.status) }}。{{ timeline.coverage.note }}</p><div class="upgrade-actions"><el-tag v-for="sensor in timeline.coverage.sensors" :key="sensor.sensor_id">{{ sensor.sensor_id }} · {{ coverageLabel(sensor.status) }} · {{ sensor.age_seconds }} 秒前</el-tag></div>
      <DataTable :rows="timeline.events" max-height="320"><el-table-column prop="timestamp" label="事件时间" min-width="190" /><el-table-column prop="process_name" label="进程" min-width="135" /><el-table-column prop="pid" label="PID" width="85" /><el-table-column prop="category" label="事件类别" min-width="150" /><el-table-column label="目标" min-width="190"><template #default="{ row }">{{ row.file_path || row.destination || '—' }}{{ row.port ? ':' + row.port : '' }}</template></el-table-column><el-table-column prop="process_key" label="进程关联依据" min-width="240" show-overflow-tooltip /></DataTable><el-empty v-if="!timeline.events.length" description="该资产暂无事件；这不能证明不存在风险" />
      <p class="operation-help">{{ timeline.processes.length }} 个进程分组 · {{ timeline.edges.length }} 条有明确父进程标识的关联。{{ timeline.note }}</p>
    </template><el-empty v-else-if="!error" description="选择资产查看进程证据和采集状态" />
    <el-alert v-if="comparison" :title="'对比窗口内：修复前 ' + comparison.before.count + ' 条，修复后 ' + comparison.after.count + ' 条。' + comparison.note" type="info" :closable="false" />
  </section>
</template>
<script setup>
import { onMounted, ref } from "vue";
import { fetchAssets } from "../api";
import { errorMessage, fetchRuntimeTimeline, compareRuntime } from "../api/deviceOperations";
import DataTable from "./DataTable.vue";
const assets = ref([]); const assetId = ref(null); const checkpoint = ref(null); const timeline = ref(null); const comparison = ref(null); const loading = ref(false); const comparing = ref(false); const error = ref("");
const coverageLabel = value => ({ running: '采集器报告运行中', degraded: '采集降级', stale: '心跳过期', unknown: '覆盖未知', stopped: '已停止', unsupported: '未兼容' }[value] || value);
async function loadTimeline() { if (!assetId.value) return; loading.value = true; error.value = ''; comparison.value = null; timeline.value = null; try { timeline.value = await fetchRuntimeTimeline(assetId.value); } catch (e) { error.value = errorMessage(e); } finally { loading.value = false; } }
async function compare() { comparing.value = true; error.value = ''; try { comparison.value = await compareRuntime(assetId.value, { checkpoint: checkpoint.value.toISOString(), window_seconds: 300 }); } catch (e) { error.value = errorMessage(e); } finally { comparing.value = false; } }
onMounted(async () => { try { assets.value = await fetchAssets(); } catch (e) { error.value = errorMessage(e); } });
</script>
