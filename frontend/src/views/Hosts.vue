<template>
  <div class="page">
    <PageHeader
      title="主机资产"
      subtitle="HOST INVENTORY"
      description="Linux 主机台账来自采集脚本的真实输出：发行版与内核取自 /etc/os-release、uname，软件包取自 dpkg/rpm，监听端口取自 ss。每一行都能回到原始采集文本与它的 sha256。"
    >
      <template #meta>
        <span class="mono h-count">{{ assets.length }} 台</span>
        <span class="h-dot">·</span>
        <span>{{ updatedLabel }}</span>
      </template>
      <template #actions>
        <button class="btn" type="button" @click="printView"><Icon name="printer" :size="15" />打印</button>
        <button class="btn primary" type="button" :disabled="loading" @click="load">
          <Icon name="refresh" :size="15" />{{ loading ? "读取中…" : "重新读取" }}
        </button>
      </template>
    </PageHeader>

      <VerdictRuling
        :state="ruling.state"
        :stamp-main="ruling.stampMain"
        :stamp-en="ruling.stampEn"
        :title="ruling.title"
        :detail="ruling.detail"
        :tags="ruling.tags"
      />

    <p v-if="error" class="error-banner" role="alert">
      <Icon name="alert" :size="15" />{{ error }}
    </p>

    <div class="kpi-row">
      <KpiCard label="已接入主机" :value="assets.length" icon="server" tone="blue"
               :sub="distributionLabel" />
      <KpiCard label="软件包合计" :value="packageTotal" icon="archive" tone="purple"
               :sub="incompleteCount ? `${incompleteCount} 台清单不完整` : '清单均标记为完整'" />
      <KpiCard label="公开暴露" :value="publicCount" icon="radio" :tone="publicCount ? 'red' : 'green'"
               sub="ss 检测到非回环监听" />
      <KpiCard label="已评估风险" :value="assessedCount" icon="bug" :tone="assessedCount ? 'orange' : 'blue'"
               sub="未评估不代表安全" />
    </div>

    <section v-if="!loading && !assets.length" class="card h-empty">
      <h2 class="card-title">尚未接入主机</h2>
      <p class="h-empty-copy">
        业务库里没有任何 Linux 主机记录。在目标主机上执行仓库自带的采集脚本，再把输出上传到
        <span class="mono">POST /api/assets/upload</span>，本页就会出现真实台账：
      </p>
      <pre class="h-cmd mono">bash collector/collect_linux_asset.sh /tmp/linux_asset.txt</pre>
      <pre class="h-cmd mono">python _work/upload_asset.py /tmp/linux_asset.txt</pre>
      <p class="h-empty-foot">没有采集结果就保持空白并给出可执行的下一步，不摆示例主机。</p>
    </section>

    <section v-else class="card h-table">
      <div class="card-head">
        <div>
          <h2 class="card-title">主机台账</h2>
          <div class="card-desc">点任意一行查看包清单、监听端口与采集元数据；字段为空表示采集脚本未取到，不用默认值填空。</div>
        </div>
        <span class="chip muted">来源 <b class="mono">{{ sourceSummary }}</b></span>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">主机名</th>
              <th scope="col">地址</th>
              <th scope="col">发行版</th>
              <th scope="col">内核</th>
              <th scope="col">架构</th>
              <th scope="col">暴露面</th>
              <th scope="col" class="h-r">软件包</th>
              <th scope="col" class="h-r">服务</th>
              <th scope="col">采集时间</th>
              <th scope="col">风险</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in assets" :key="row.id" tabindex="0" role="button"
                @click="openDetail(row)" @keydown.enter="openDetail(row)">
              <td>
                <b>{{ row.hostname || "未命名" }}</b>
                <div class="h-sub mono">{{ row.distribution || "发行版未知" }} · id {{ row.id }}</div>
              </td>
              <td class="mono">{{ row.ip_address || "—" }}</td>
              <td>{{ osLabel(row) }}</td>
              <td class="mono h-kernel" :title="row.kernel_version || ''">{{ kernelLabel(row) }}</td>
              <td class="mono">{{ row.architecture || "—" }}</td>
              <td>
                <span class="chip" :class="exposureTone(row.exposure_level)">
                  <i class="dot" />{{ exposureLabel(row.exposure_level) }}
                </span>
              </td>
              <td class="h-r mono">{{ row.package_count ?? packageCountFallback(row) }}</td>
              <td class="h-r mono">{{ row.service_count ?? "—" }}</td>
              <td class="mono">{{ timeLabel(row.inventory_collected_at) }}</td>
              <td>
                <span v-if="row.risk_level && Number(row.risk_score) > 0" class="chip" :class="riskTone(row.risk_level)">
                  <i class="dot" />{{ row.risk_level }} {{ row.risk_score }}
                </span>
                <span v-else-if="row.risk_level" class="chip mid" :title="`最终分尚未产生（current=${row.risk_score ?? 0}），需四智能体研判与人工裁决`">
                  <i class="dot" />待研判
                </span>
                <span v-else class="chip muted"><i class="dot" />未评估</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p class="h-note">
        共 {{ assets.length }} 台主机；软件包合计 {{ packageTotal.toLocaleString("zh-CN") }} 条。
        台账里的“未评估”指漏洞匹配尚未对这台主机执行，不等于没有漏洞。
      </p>
    </section>

    <section v-if="assets.length" class="card h-evidence">
      <div class="card-head">
        <div>
          <h2 class="card-title">采集证据</h2>
          <div class="card-desc">每台主机的清单都对应一份原始采集文本；这里列出解析统计与文件哈希，便于复核“这行数据从哪来”。</div>
        </div>
        <span class="chip muted">按 {{ assets.length }} 台汇总</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">主机</th>
              <th scope="col">来源格式</th>
              <th scope="col">包解析</th>
              <th scope="col">丢弃</th>
              <th scope="col">原始文件 sha256</th>
              <th scope="col">采集时间</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in assets" :key="'ev-' + row.id">
              <td><b>{{ row.hostname || "未命名" }}</b></td>
              <td>{{ formatLabel(row) }}</td>
              <td class="mono">{{ parseStats(row) }}</td>
              <td class="mono">{{ metadataOf(row).package_parse_stats?.rejected_count ?? "—" }}</td>
              <td class="mono h-sha" :title="row.inventory_sha256 || ''">{{ shortHash(row.inventory_sha256) }}</td>
              <td class="mono">{{ timeLabel(row.inventory_collected_at) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <Modal :open="Boolean(detail)" :title="detail ? detail.hostname : ''" wide
           description="身份、软件包与监听端口的原始采集结果" @close="detail = null">
      <template v-if="detail">
        <div class="h-field-grid">
          <div v-for="field in detailFields" :key="field.label" class="h-field">
            <span>{{ field.label }}</span>
            <b :class="field.mono ? 'mono' : ''">{{ field.value }}</b>
          </div>
        </div>

        <h3 class="h-sec">监听端口（{{ detail.services.length }}）</h3>
        <div class="table-wrap">
          <table v-if="detail.services.length">
            <thead>
              <tr>
                <th scope="col">端口</th>
                <th scope="col">协议</th>
                <th scope="col">监听地址</th>
                <th scope="col">服务</th>
                <th scope="col">公网暴露</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(svc, index) in detail.services" :key="index">
                <td class="mono">{{ svc.port ?? "—" }}</td>
                <td class="mono">{{ svc.protocol || "—" }}</td>
                <td class="mono">{{ svc.listen_address || "—" }}</td>
                <td>{{ svc.service_name || svc.process_name || "未识别" }}</td>
                <td>
                  <span class="chip" :class="svc.is_public_exposed ? 'crit' : 'muted'">
                    <i class="dot" />{{ svc.is_public_exposed ? "是" : "否" }}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
          <p v-else class="h-empty-foot">采集文本里没有解析到监听端口段。</p>
        </div>

        <h3 class="h-sec">
          软件包（{{ detail.packages.length }}）
          <span class="h-sec-note">显示前 {{ shownPackages.length }} 条，可按名称筛选</span>
        </h3>
        <input v-model="packageQuery" class="input h-search" type="search" placeholder="筛选包名，例如 openssl / libssl / systemd" />
        <div class="table-wrap h-pkg-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">包名</th>
                <th scope="col">版本</th>
                <th scope="col">包管理器</th>
                <th scope="col">架构</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="pkg in shownPackages" :key="pkg.package_name + pkg.package_version">
                <td class="mono">{{ pkg.package_name }}</td>
                <td class="mono">{{ pkg.package_version }}</td>
                <td class="mono">{{ pkg.package_manager }}</td>
                <td class="mono">{{ pkg.architecture || "—" }}</td>
              </tr>
            </tbody>
          </table>
          <p v-if="!shownPackages.length" class="h-empty-foot">没有匹配的软件包。</p>
        </div>

        <h3 class="h-sec">采集元数据</h3>
        <pre class="h-json mono">{{ metadataText }}</pre>
      </template>
    </Modal>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import PageHeader from "../components/PageHeader.vue";
import VerdictRuling from "../components/VerdictRuling.vue";
import Icon from "../components/Icon.vue";
import KpiCard from "../components/KpiCard.vue";
import Modal from "../components/Modal.vue";
import { api } from "../api";

const assets = ref([]);
const loading = ref(true);
const error = ref("");
const updated = ref("");
const detail = ref(null);
const packageQuery = ref("");
const PACKAGE_ROWS = 120;

const EXPOSURE = { public: "公开", dmz: "隔离区", internal: "内网" };
const EXPOSURE_TONE = { public: "crit", dmz: "high", internal: "low" };
const RISK_TONE = { Critical: "crit", High: "high", Medium: "mid", Low: "low" };

function exposureLabel(value) {
  return EXPOSURE[value] || value || "未标注";
}
function exposureTone(value) {
  return EXPOSURE_TONE[value] || "muted";
}
function riskTone(value) {
  return RISK_TONE[value] || "muted";
}
function osLabel(row) {
  if (!row.os_name) return "—";
  return row.os_version ? `${row.os_name} ${row.os_version}` : row.os_name;
}
/** 内核字段可能是整行 uname -a，这里只取内核版本号，完整串放 title。 */
function kernelLabel(row) {
  const raw = String(row.kernel_version || "");
  if (!raw) return "—";
  const match = raw.match(/\b(\d+\.\d+\.\d+[\w.+-]*)\b/);
  return match ? match[1] : raw.slice(0, 24);
}
function packageCountFallback(row) {
  const stats = row.inventory_metadata && row.inventory_metadata.package_parse_stats;
  return stats && Number.isFinite(Number(stats.parsed_count)) ? Number(stats.parsed_count) : "—";
}
const FORMAT_LABEL = {
  sectioned_text: "分段采集文本",
  "openwrt_export_1.0": "OpenWrt 导出 JSON 1.0",
  iotguard_asset_v1: "资产 JSON v1"
};

function metadataOf(row) {
  return (row && row.inventory_metadata) || {};
}
function formatLabel(row) {
  const raw = metadataOf(row).format || row.identity_source || "";
  return FORMAT_LABEL[raw] || raw || "—";
}
function parseStats(row) {
  const stats = metadataOf(row).package_parse_stats;
  if (!stats) return "—";
  const parsed = stats.parsed_count ?? stats.parsedCount;
  const raw = stats.raw_count ?? stats.rawCount;
  return parsed != null && raw != null ? `${parsed} / ${raw}` : String(parsed ?? "—");
}
function shortHash(value) {
  const text = String(value || "");
  if (!text) return "未记录";
  return text.length <= 20 ? text : `${text.slice(0, 10)}…${text.slice(-6)}`;
}
function timeLabel(value) {  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("zh-CN", { hour12: false });
}

const updatedLabel = computed(() => (updated.value ? `读取于 ${updated.value}` : "尚未读取"));
const distributionLabel = computed(() => {
  const names = Array.from(new Set(assets.value.map((row) => row.distribution).filter(Boolean)));
  return names.length ? names.join(" / ") : "无发行版信息";
});
const packageTotal = computed(() =>
  assets.value.reduce((sum, row) => {
    const fallback = packageCountFallback(row);
    return sum + (Number.isFinite(Number(fallback)) ? Number(fallback) : 0);
  }, 0));
const publicCount = computed(() => assets.value.filter((row) => row.exposure_level === "public").length);
const incompleteCount = computed(() => assets.value.filter((row) => row.inventory_complete === false).length);
const assessedCount = computed(() => assets.value.filter((row) => row.risk_level || row.risk_assessment_status === "current").length);

/* 页面级状态印章：主机页回答"清单与评估是否闭环" */
const ruling = computed(() => {
  const total = assets.value.length;
  const incomplete = incompleteCount.value;
  const assessed = assessedCount.value;
  const exposed = publicCount.value;
  const tags = [
    { text: `主机 ${total} 台`, tone: "" },
    { text: `公网暴露 ${exposed}`, tone: exposed > 0 ? "high" : "" },
    { text: `清单待补 ${incomplete}`, tone: incomplete > 0 ? "mid" : "" },
    { text: `已评估 ${assessed}`, tone: assessed === total && total > 0 ? "low" : "mid" },
  ];
  if (total === 0) {
    return {
      state: "weak", stampMain: "无数据", stampEn: "NO DATA",
      title: "当前没有主机资产记录",
      detail: "没有记录不代表没有主机：需要先完成采集或导入主机清单。",
      tags,
    };
  }
  if (incomplete > 0 || assessed < total) {
    return {
      state: "weak", stampMain: "未闭环", stampEn: "OPEN LOOP",
      title: `${total} 台主机中，${total - assessed} 台尚未评估`,
      detail: "清单或评估缺失会让组件级漏洞匹配失去依据；未评估不等于安全。",
      tags,
    };
  }
  return {
    state: "pass", stampMain: "已闭环", stampEn: "CLOSED",
    title: `${total} 台主机清单与评估均已闭环`,
    detail: `其中公网暴露 ${exposed} 台；该结论覆盖已登记主机。`,
    tags,
  };
});
const sourceSummary = computed(() => {
  const names = Array.from(new Set(assets.value.map((row) => row.identity_source).filter(Boolean)));
  return names.length ? names.join(" / ") : "未记录";
});

const detailFields = computed(() => {
  const row = detail.value;
  if (!row) return [];
  return [
    { label: "台账 id", value: row.id, mono: true },
    { label: "主机名", value: row.hostname || "—" },
    { label: "地址", value: row.ip_address || "—", mono: true },
    { label: "系统", value: osLabel(row) },
    { label: "架构", value: row.architecture || "—", mono: true },
    { label: "内核", value: row.kernel_version || "—", mono: true },
    { label: "暴露等级", value: exposureLabel(row.exposure_level) },
    { label: "业务等级", value: row.business_level || "—" },
    { label: "设备类型", value: row.device_type || "—", mono: true },
    { label: "身份来源", value: row.identity_source || "—", mono: true },
    { label: "身份可信度", value: row.identity_confidence != null ? `${Math.round(Number(row.identity_confidence) * 100)}%` : "—" },
    { label: "清单完整", value: row.inventory_complete ? "是" : "否" },
    { label: "采集时间", value: timeLabel(row.inventory_collected_at) },
    { label: "原始文件 sha256", value: row.inventory_sha256 || "未记录", mono: true }
  ];
});

const metadataText = computed(() => JSON.stringify(detail.value ? detail.value.inventory_metadata : {}, null, 2));

const shownPackages = computed(() => {
  const list = (detail.value && detail.value.packages) || [];
  const query = packageQuery.value.trim().toLowerCase();
  const filtered = query ? list.filter((pkg) => String(pkg.package_name || "").toLowerCase().includes(query)) : list;
  return filtered.slice(0, PACKAGE_ROWS);
});

async function load() {  loading.value = true;
  error.value = "";
  try {
    const [list, overview] = await Promise.allSettled([
      api.get("/assets", { timeout: 25000 }),
      api.get("/devices/business/overview", { timeout: 25000 })
    ]);
    if (list.status !== "fulfilled" || !Array.isArray(list.value.data)) {
      throw new Error(list.status === "rejected" ? (list.reason?.message || "接口不可用") : "返回格式不是数组");
    }
    // 业务总览只带 IoT 设备；主机清单的包/服务计数在详情里，列表用元数据里的解析统计，
    // 再按详情补齐真实条数（主机数量少，逐台读取可接受；超过 12 台就不再补）。
    assets.value = await enrich(list.value.data);
    updated.value = new Date().toLocaleTimeString("zh-CN", { hour12: false });
    if (overview.status !== "fulfilled") {
      error.value = "业务总览读取失败；主机清单仍按 /api/assets 的真实返回展示。";
    }
  } catch (exc) {
    error.value = `读取主机清单失败：${exc?.message || exc}`;
    assets.value = [];
  } finally {
    loading.value = false;
  }
}

async function enrich(rows) {
  const list = rows.map((row) => ({ ...row }));
  for (const row of list.slice(0, 12)) {
    try {
      const response = await api.get(`/assets/${row.id}`, { timeout: 20000 });
      row.package_count = (response.data.packages || []).length;
      row.service_count = (response.data.services || []).length;
      row.inventory_metadata = response.data.inventory_metadata || row.inventory_metadata;
    } catch {
      /* 详情读不到就保留列表字段，不用猜测值填 */
    }
  }
  return list;
}

async function openDetail(row) {
  packageQuery.value = "";
  try {
    const response = await api.get(`/assets/${row.id}`, { timeout: 25000 });
    detail.value = response.data;
  } catch (exc) {
    error.value = `读取主机 ${row.hostname || row.id} 详情失败：${exc?.message || exc}`;
  }
}

function printView() {
  window.print();
}

onMounted(load);
</script>

<style scoped>
/* align-content:start 不能省：页面容器有确定高度时，grid 会把富余高度摊给
   auto 行，KPI 卡片会被拉高到 236px（实测）。 */
.page { display: grid; gap: 12px; align-content: start; }

/* 字号统一走全站字阶（styles/redesign/tokens.css 的 --fs-*）：投影可读下限 13px。 */
.page :deep(th) { color: var(--ink-3); font-size: var(--fs-micro); }

.h-count { letter-spacing: -0.02em; }
.h-dot { padding: 0 2px; }

.kpi-row { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }

.h-table .table-wrap { overflow-x: auto; }
.h-table tbody tr { cursor: pointer; }
.h-table tbody tr:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
.h-sub { margin-top: 2px; color: var(--ink-3); font-size: var(--fs-micro); }
.h-kernel { max-width: 130px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.h-r { text-align: right; }
.h-note { margin: 12px 16px 16px; color: var(--ink-3); font-size: var(--fs-micro); line-height: 1.6; }
.h-sha { max-width: 190px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.h-evidence .table-wrap { overflow-x: auto; }

.h-empty { padding: 16px 16px; display: grid; gap: 8px; }
.h-empty-copy { color: var(--ink-2); font-size: var(--fs-body); line-height: 1.6; max-width: 88ch; }
.h-empty-foot { color: var(--ink-3); font-size: var(--fs-micro); }
.h-cmd {
  margin: 0; padding: 8px 12px; border-radius: var(--radius-sm);
  background: var(--surface-2); border: 1px solid var(--line);
  color: var(--ink); font-size: var(--fs-meta); overflow-x: auto;
}

.h-field-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px 16px; }
.h-field { display: grid; gap: 2px; min-width: 0; }
.h-field span { color: var(--ink-3); font-size: var(--fs-micro); }
.h-field b { color: var(--ink); font-size: var(--fs-body); font-weight: 600; overflow-wrap: anywhere; }

.h-sec { margin: 18px 0 8px; font-size: var(--fs-title-sm); font-weight: 700; color: var(--ink); }
.h-sec-note { margin-left: 8px; color: var(--ink-3); font-size: var(--fs-micro); font-weight: 500; }
.h-search { margin-bottom: 8px; max-width: 360px; }
.h-pkg-wrap { max-height: 46vh; overflow: auto; }
.h-json {
  margin: 0; max-height: 30vh; overflow: auto; padding: 12px;
  border-radius: var(--radius-sm); background: var(--surface-2); border: 1px solid var(--line);
  color: var(--ink-2); font-size: var(--fs-meta); line-height: 1.55;
}

@media (max-width: 1100px) {
  .kpi-row { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .h-field-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

@media (max-width: 760px) {
  .kpi-row, .h-field-grid { grid-template-columns: minmax(0, 1fr); }
  .btn { min-height: 36px; }
  tbody td { padding-top: 8px; padding-bottom: 8px; }
}

@media print {
  .h-table .table-wrap, .h-pkg-wrap { overflow: visible; max-height: none; }
  .btn { display: none; }
}
</style>
