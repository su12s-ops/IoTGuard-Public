<template>
  <section class="page">
    <div class="explain">
      LinuxGuard 不是看到 CVE 就直接报警，而是把漏洞影响软件包、资产实际安装版本和修复版本进行对比，输出资产级命中依据。
    </div>
    <el-card class="panel" shadow="never">
      <div class="toolbar">
        <el-button type="primary" :icon="Connection" @click="run">执行漏洞命中分析</el-button>
        <el-switch v-model="affectedOnly" active-text="只看命中" inactive-text="全部结果" />
      </div>
    </el-card>
    <el-card class="panel" shadow="never">
      <DataTable :rows="filtered">
        <el-table-column prop="hostname" label="主机名" width="150" />
        <el-table-column prop="cve_id" label="CVE" width="140" />
        <el-table-column prop="package_name" label="软件包" width="130" />
        <el-table-column prop="installed_version" label="当前版本" width="170" />
        <el-table-column prop="fixed_version" label="修复版本" width="170" />
        <el-table-column label="是否命中" width="110">
          <template #default="{ row }">
            <el-tag :type="row.affected ? 'danger' : 'success'">{{ row.affected ? "命中" : "未命中" }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="confidence" label="置信度" width="90" />
        <el-table-column prop="match_reason" label="判断依据" min-width="360" />
      </DataTable>
    </el-card>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import { ElMessage } from "element-plus";
import { Connection } from "@element-plus/icons-vue";
import DataTable from "../components/DataTable.vue";
import { fetchMatches, runMatching } from "../api";

const rows = ref([]);
const affectedOnly = ref(true);
const filtered = computed(() => (affectedOnly.value ? rows.value.filter((row) => row.affected) : rows.value));

const load = async () => {
  rows.value = await fetchMatches();
};
const run = async () => {
  const result = await runMatching();
  ElMessage.success(`命中分析完成：${result.count} 条结果`);
  await load();
};

onMounted(load);
</script>

