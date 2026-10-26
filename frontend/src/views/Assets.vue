<template>
  <div class="page">
    <PageHeader
      title="资产与发现"
      subtitle="Asset & Asset Discovery"
      description="设备身份、组件清单与原始观测分开记录"
    >
      <template #meta>
        <span>{{ devices.length }} 台设备</span><i class="sep" /><span>{{ num(componentCount) }} 个组件</span><i class="sep" /><span>{{ trustedCount }}/{{ devices.length }} 身份可信</span><i class="sep" /><span>{{ incompleteCount }} 份清单待补</span>
      </template>
      <template #actions>
        <button class="btn" type="button" @click="load"><Icon name="refresh" :size="15" />刷新</button>
        <button class="btn" type="button" @click="openAdvisory"><Icon name="file" :size="15" />OpenWrt 公告登记</button>
        <button class="btn" type="button" :disabled="uploading" @click="pickImport"><Icon name="download" :size="15" />{{ uploading ? "导入中…" : "导入清单" }}</button>
        <button class="btn primary" type="button" @click="openDiscovery"><Icon name="scan" :size="15" />发现新设备</button>
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

    <input ref="fileInput" type="file" accept=".json,.txt,.csv,.md" hidden @change="importAsset" />

    <div v-if="error" class="error-banner" role="alert"><Icon name="alert" :size="15" />{{ error }}</div>

    <div class="kpi-row">
      <KpiCard label="设备总数" :value="num(devices.length)" unit="台" icon="server" tone="blue" :sub="`${ecosystemCount} 个生态 · ${num(componentCount)} 个组件`" />
      <KpiCard label="身份可信" :value="num(trustedCount)" unit="台" icon="shield" tone="green" :sub="`${trustRate} · 可信度 ≥ 90%`" />
      <KpiCard label="清单待补" :value="num(incompleteCount)" unit="台" icon="layers" tone="orange" :sub="`${devices.length - incompleteCount} 台清单完整`" />
      <KpiCard label="未识别设备" :value="num(unidentifiedCount)" unit="台" icon="scan" tone="purple" :sub="`版本缺失或身份可信度低`" />
    </div>

    <div class="asset-grid">
      <section class="card type-card">
        <div class="card-head">
          <div><div class="card-title">设备类型</div><div class="card-desc">按设备台账计数</div></div>
        </div>
        <div class="type-list">
          <button class="type-row" :class="{ active: eco === 'all' }" type="button" @click="setEco('all')">
            <span class="type-ic" style="background: #eef4ff; color: #2f6fed"><Icon name="layers" :size="16" /></span>
            <span class="type-name">全部设备</span>
            <b class="num">{{ devices.length }}</b>
            <Icon name="chev-right" :size="13" class="type-chev" />
          </button>
          <button
            v-for="item in typeItems"
            :key="item.value"
            class="type-row"
            :class="{ active: eco === item.value }"
            type="button"
            @click="setEco(item.value)"
          >
            <span class="type-ic" :style="{ background: item.soft, color: item.color }"><Icon :name="item.icon" :size="16" /></span>
            <span class="type-name">{{ item.label }}</span>
            <b class="num">{{ item.count }}</b>
            <Icon name="chev-right" :size="13" class="type-chev" />
          </button>
        </div>
        <div class="type-sep">
          <div class="type-sep-title">身份可信度</div>
          <div v-for="bucket in confidenceBuckets" :key="bucket.label" class="bucket-row">
            <span>{{ bucket.label }}</span>
            <span class="bucket-track"><i :class="bucket.tone" :style="{ width: bucket.width }" /></span>
            <b class="num">{{ bucket.count }}</b>
          </div>
        </div>
        <div class="type-foot">
          <span>身份来源：SSH 清单 / HTTP 端点 / banner 指纹</span>
        </div>
      </section>

      <section class="card map-card">
        <div class="card-head">
          <div><div class="card-title">设备拓扑视图</div><div class="card-desc">按生态分组 · 点击类型可筛选清单</div></div>
          <div class="segmented">
            <span :class="{ active: view === 'map' }" @click="view = 'map'">拓扑图</span>
            <span :class="{ active: view === 'list' }" @click="view = 'list'">列表视图</span>
          </div>
        </div>
        <div v-if="view === 'map'" class="map-body">
          <div class="map-legend">
            <span v-for="item in typeItems" :key="item.value"><i class="dot" :style="{ background: item.color }" />{{ item.label }}<b>{{ item.count }}</b></span>
          </div>
          <TopologyMap :nodes="topologyNodes" :height="360" />
          <div class="map-foot">
            <span>按生态归并 · {{ devices.length }} 台设备</span>
            <span class="num">{{ num(componentCount) }} 个组件</span>
          </div>
        </div>
        <div v-else class="table-wrap map-list">
          <table style="table-layout: fixed">
            <colgroup><col style="width: 190px" /><col style="width: 88px" /><col style="width: 102px" /><col style="width: 52px" /><col style="width: 94px" /><col style="width: 94px" /></colgroup>
            <thead><tr><th>设备</th><th>生态</th><th>系统 / 固件</th><th>组件</th><th>身份可信</th><th>漏洞命中</th></tr></thead>
            <tbody>
              <tr v-for="device in filteredDevices" :key="device.key" style="cursor: pointer" tabindex="0" role="button" @click="openDetail(device)" @keydown.enter="openDetail(device)">
                <td class="name">{{ device.name || device.key }}<small>{{ device.ip_address || device.key }}</small></td>
                <td><span class="chip" :class="ecoClass(device.ecosystem)"><i class="dot" />{{ ecosystemLabel(device.ecosystem) }}</span></td>
                <td><span class="mono">{{ device.version || "未识别" }}</span><small>{{ device.inventory_complete === false ? "清单待补" : "清单完整" }}</small></td>
                <td class="num">{{ device.component_count ?? "—" }}</td>
                <td><span class="chip" :class="identityTone(device.identity_confidence)"><i class="dot" />{{ ratioPct(device.identity_confidence, 0) }}</span></td>
                <td><span class="chip" :class="device.matches?.confirmed ? 'crit' : device.matches?.pending ? 'high' : 'muted'"><i class="dot" />{{ device.matches?.confirmed ?? 0 }} 确认</span></td>
              </tr>
            </tbody>
          </table>
          <div v-if="!filteredDevices.length" class="empty-note" style="padding: 30px 18px">当前类型暂无设备。</div>
        </div>
      </section>

      <section class="card recent-card">
        <div class="card-head">
          <div><div class="card-title">最近发现的设备</div><div class="card-desc">按清单采集时间排序</div></div>
          <button class="link" type="button" @click="view = 'list'">更多 <Icon name="chev-right" :size="12" /></button>
        </div>
        <div class="recent-list">
          <button v-for="device in recentDevices" :key="device.key" class="recent-row" type="button" @click="openDetail(device)">
            <span class="recent-ic" :style="{ background: ecoMeta(device.ecosystem).soft, color: ecoMeta(device.ecosystem).color }">
              <Icon :name="ecoMeta(device.ecosystem).icon" :size="18" />
            </span>
            <span class="recent-copy">
              <b>{{ device.name || device.key }}</b>
              <small>{{ device.ip_address || (device.version ? `v${device.version}` : "地址未记录") }}</small>
            </span>
            <span class="recent-time">{{ device.inventory_collected_at ? timeAgoText(device.inventory_collected_at) : "已登记" }}</span>
            <Icon name="chev-right" :size="13" class="recent-chev" />
          </button>
          <div v-if="!recentDevices.length" class="empty-note" style="padding: 24px 18px">暂无设备记录，完成一次发现后即可看到。</div>
        </div>
        <div class="recent-foot"><span class="dot ok" />实时台账 · 最近同步 {{ updated || "尚未读取" }}</div>
      </section>
    </div>

    <section class="card">
      <div class="card-head">
        <div><div class="card-title">采集覆盖</div><div class="card-desc">身份、清单与评估是三条独立链路</div></div>
        <div class="row">
          <button class="link" type="button" @click="exportCsv"><Icon name="download" :size="13" />导出 CSV</button>
          <span class="chip muted">最近同步 {{ updated || "尚未读取" }}</span>
        </div>
      </div>
      <div v-if="!coverageDevices.length" class="empty-note" style="padding: 18px">暂无覆盖记录。</div>
      <div v-else class="cover-grid">
        <div v-for="device in coverageDevices" :key="device.key" class="cover">
          <div class="cover-name"><i class="dot" :style="{ background: ecoMeta(device.ecosystem).color }" />{{ device.name || device.key }}</div>
          <div class="cover-row"><span>身份</span><span class="cover-bar"><i :class="pctClass(device.identity_confidence)" :style="{ width: ratioPct(device.identity_confidence) }" /></span><span class="cover-val">{{ ratioPct(device.identity_confidence, 0) }}</span></div>
          <div class="cover-row"><span>清单</span><span class="cover-bar"><i :class="device.inventory_complete === false ? 'warn' : 'low'" :style="{ width: device.inventory_complete === false ? '40%' : device.inventory_complete ? '100%' : '0%' }" /></span><span class="cover-val">{{ device.inventory_complete === false ? "40%" : device.inventory_complete ? "100%" : "—" }}</span></div>
          <div class="cover-row"><span>评估</span><span class="cover-bar"><i :class="assessmentClass(device.matches?.assessment)" :style="{ width: assessmentWidth(device.matches?.assessment) }" /></span><span class="cover-val">{{ assessmentLabel(device.matches?.assessment) }}</span></div>
        </div>
      </div>
      <div class="card-foot"><span>身份可信度来自 SSH 清单、HTTP 身份端点与 banner 指纹；三者不等价。</span><span>{{ devices.length }} 台设备</span></div>
    </section>

    <Modal :open="Boolean(selected)" :title="selected?.name || '设备详情'" description="台账字段来自后端观测；未知字段不推测。" wide @close="selected = null">
      <div v-if="selected" class="detail-tabs segmented" role="tablist" aria-label="设备详情视图">
        <span role="tab" tabindex="0" :aria-selected="detailTab === 'overview'" :class="{ active: detailTab === 'overview' }" @click="detailTab = 'overview'" @keydown.enter="detailTab = 'overview'">台账详情</span>
        <span role="tab" tabindex="0" :aria-selected="detailTab === 'collection'" :class="{ active: detailTab === 'collection' }" @click="detailTab = 'collection'" @keydown.enter="detailTab = 'collection'">连接与采集</span>
        <span role="tab" tabindex="0" :aria-selected="detailTab === 'analysis'" :class="{ active: detailTab === 'analysis' }" @click="detailTab = 'analysis'" @keydown.enter="detailTab = 'analysis'">分析研判</span>
      </div>
      <div v-if="selected && detailTab === 'overview'" class="detail-grid">
        <div><span>台账键</span><b class="mono">{{ selected.key }}</b></div>
        <div><span>IP 地址</span><b class="mono">{{ selected.ip_address || "—" }}</b></div>
        <div><span>生态</span><b>{{ ecosystemLabel(selected.ecosystem) }}</b></div>
        <div><span>版本</span><b class="mono">{{ selected.version || "未识别" }}</b></div>
        <div><span>组件</span><b>{{ selected.component_count ?? "—" }}</b></div>
        <div><span>身份可信度</span><b>{{ ratioPct(selected.identity_confidence, 0) }}</b></div>
        <div><span>有效软件清单</span><b>{{ selected.inventory_complete && Number(selected.component_count) > 0 ? `是 · ${selected.component_count} 个组件` : "否 · 仅发现或清单待补" }}</b></div>
        <div><span>最近清单采集</span><b>{{ selected.inventory_collected_at ? formatBackendTime(selected.inventory_collected_at) : "未记录" }}</b></div>
        <div><span>漏洞命中</span><b>{{ selected.matches?.count ?? "—" }} 条</b></div>
        <div><span>运行时</span><b>{{ runtimeLabel(selected.runtime) }}</b></div>
        <div><span>修复能力</span><b>{{ remediationLabel(selected.remediation) }}</b></div>
        <div class="wide">
          <span>修复授权域</span>
          <b>
            <span class="chip" :class="selected.repair_domain === 'openwrt_lab' ? 'low' : selected.repair_domain === 'production' ? 'crit' : 'muted'"><i class="dot" />{{ repairDomainLabel(selected.repair_domain) }}</span>
            <small v-if="selected.repair_domain_actor" class="domain-note">登记人 {{ selected.repair_domain_actor }}；一次性登记，不可改写</small>
            <button
              v-if="canEnrollRepairDomain"
              class="link enroll-link"
              type="button"
              @click="domainOpen = true"
            >登记修复授权域</button>
          </b>
        </div>
        <div class="wide"><span>下一步</span><b>{{ nextActionLabel(selected.next_action) }}</b></div>
      </div>
      <DeviceCollectionPanel v-else-if="selected && detailTab === 'collection'" :asset="selected" :open="true" @updated="onCollectionUpdated" />
      <AssetAnalysisPanel v-else-if="selected && detailTab === 'analysis'" :asset="selected" :refresh-key="analysisRefresh" @started="onAnalysisStarted" />
      <template #footer>
        <template v-if="detailTab === 'overview'">
          <button class="btn" type="button" :disabled="!selected?.asset_id" :title="selected?.asset_id ? '配置连接、预检并采集软件清单' : '仅已登记的 OpenWrt/Ubuntu 主机资产支持连接与采集'" @click="detailTab = 'collection'"><Icon name="activity" :size="14" />连接与采集</button>
          <button class="btn primary" type="button" :disabled="!selected?.asset_id" :title="selected?.asset_id ? '匹配 → 风险计算 → 四智能体研判' : '仅已登记的资产支持分析'" @click="detailTab = 'analysis'"><Icon name="cpu" :size="14" />分析研判</button>
        </template>
        <button v-else class="btn" type="button" @click="detailTab = 'overview'">返回台账</button>
        <button class="btn" type="button" @click="selected = null">关闭</button>
      </template>
    </Modal>

    <Modal :open="discoveryOpen" title="发起授权发现" description="只扫描显式授权网段；没有响应不等于设备不存在。" @close="discoveryOpen = false">
      <label class="field-label" for="discovery-cidr">授权网段（CIDR）</label>
      <input id="discovery-cidr" v-model="cidr" class="input" placeholder="例如 192.168.100.0/24" />
      <label class="field-label" for="discovery-ports">TCP 端口（逗号分隔）</label>
      <input id="discovery-ports" v-model="ports" class="input" placeholder="22, 80, 443" />
      <label class="checkbox-row"><input v-model="enroll" type="checkbox" /> 发现后自动入档（写入设备台账）</label>
      <p class="field-hint">发现过程可能持续数十秒；接口需要操作令牌。仅对授权目标使用。</p>
      <template #footer>
        <button class="btn" type="button" @click="discoveryOpen = false">取消</button>
        <button class="btn primary" type="button" :disabled="discovering || !cidr.trim()" @click="submitDiscovery">{{ discovering ? "发现中…" : "开始发现" }}</button>
      </template>
    </Modal>

    <Modal :open="domainOpen" title="登记修复授权域" description="一次性登记，登记后不能通过此入口改写；修复执行还需产物登记与作用域写窗口。" @close="domainOpen = false">
      <div class="plan-rows-mini" v-if="selected">
        <div><span>资产</span><b>asset {{ selected.asset_id }} · {{ selected.name || selected.key }} · {{ selected.version || "版本未识别" }}</b></div>
        <div><span>当前授权域</span><b>{{ repairDomainLabel(selected.repair_domain) }}</b></div>
      </div>
      <label class="field-label" for="domain-choice">授权域</label>
      <select id="domain-choice" v-model="domainChoice" class="input">
        <option value="openwrt_lab">openwrt_lab（隔离实验克隆；修复写入走实验作用域开关）</option>
        <option value="production">production（生产设备；须走生产修复总开关与独立审批）</option>
      </select>
      <label class="field-label" for="domain-actor">登记人</label>
      <input id="domain-actor" v-model="domainActor" class="input" placeholder="操作员标识（例如 wang.gong）" autocomplete="off" />
      <label class="field-label" for="domain-reason">登记依据</label>
      <textarea id="domain-reason" v-model="domainReason" class="textarea" placeholder="该资产确属隔离实验克隆 / 生产设备的依据，例如克隆来源与快照名。"></textarea>
      <p class="field-hint">授权域决定设备写许可的来源；清单、主机名或环境白名单都不能改写该字段。</p>
      <template #footer>
        <button class="btn" type="button" @click="domainOpen = false">取消</button>
        <button class="btn primary" type="button" :disabled="domainBusy || !domainActor.trim() || !domainReason.trim()" @click="submitRepairDomain">{{ domainBusy ? "登记中…" : "登记授权域" }}</button>
      </template>
    </Modal>

    <Modal :open="advisoryOpen" title="OpenWrt 公告版本登记" description="按官方公告与官方仓库登记精确受影响/已修复版本；官方 GHSA 快照导入的规范化记录不会被覆盖。" wide @close="advisoryOpen = false">
      <div class="adv-grid">
        <section class="adv-form">
          <label class="field-label" for="adv-cve">CVE 编号</label>
          <input id="adv-cve" v-model="advForm.cve_id" class="input" placeholder="CVE-2026-XXXXX" />
          <label class="field-label" for="adv-package">组件（包名）</label>
          <input id="adv-package" v-model="advForm.package_name" class="input" placeholder="cgi-io" />
          <label class="field-label" for="adv-release">固件版本（release）</label>
          <input id="adv-release" v-model="advForm.release" class="input" placeholder="25.12.4（须与资产固件版本一致才参与精确匹配）" />
          <label class="field-label" for="adv-affected">受影响版本（逗号分隔）</label>
          <input id="adv-affected" v-model="advForm.affected" class="input" placeholder="2025.12.11~658b14bd-r1" />
          <label class="field-label" for="adv-fixed">已修复版本（逗号分隔）</label>
          <input id="adv-fixed" v-model="advForm.fixed" class="input" placeholder="2026.07.21~31cb3c89-r1" />
          <label class="field-label" for="adv-url">官方来源 URL</label>
          <input id="adv-url" v-model="advForm.source_url" class="input" placeholder="官方公告或官方软件包下载地址" />
          <label class="field-label" for="adv-notes">登记依据（须可复核）</label>
          <textarea id="adv-notes" v-model="advForm.notes" class="textarea" placeholder="官方公告编号、受影响范围、镜像/仓库实测依据与校验和等。"></textarea>
          <p class="field-hint">同一 (CVE, 包, release) 已有记录将被本表单覆盖；与官方规范化记录并存时精确记录优先参与匹配。</p>
          <div class="adv-actions">
            <button class="btn" type="button" @click="advisoryOpen = false">关闭</button>
            <button class="btn primary" type="button" :disabled="advBusy || !advValid" @click="submitAdvisory">{{ advBusy ? "登记中…" : "登记版本记录" }}</button>
          </div>
        </section>
        <section class="adv-list">
          <div class="adv-list-head">已登记公告记录（{{ advisories.length }}）</div>
          <div v-if="!advisories.length" class="empty-note" style="padding: 18px">暂无记录。</div>
          <div v-for="row in advisories" :key="row.id" class="adv-row" :class="{ exact: !isNormalizedAdvisory(row) }">
            <div class="adv-row-top">
              <b class="mono">{{ row.cve_id }}</b>
              <span class="chip" :class="isNormalizedAdvisory(row) ? 'muted' : 'low'">{{ isNormalizedAdvisory(row) ? "官方规范化" : "操作员精确" }}</span>
            </div>
            <div class="adv-row-line">{{ row.package_name }} · release {{ row.release || "—" }}</div>
            <div class="adv-row-line">受影响 {{ row.affected_versions?.join(", ") || "—" }}</div>
            <div class="adv-row-line">已修复 {{ row.fixed_versions?.join(", ") || "—" }}</div>
          </div>
        </section>
      </div>
    </Modal>
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from "vue";
import PageHeader from "../components/PageHeader.vue";
import Icon from "../components/Icon.vue";
import KpiCard from "../components/KpiCard.vue";
import TopologyMap from "../components/TopologyMap.vue";
import Modal from "../components/Modal.vue";
import DeviceCollectionPanel from "../components/DeviceCollectionPanel.vue";
import AssetAnalysisPanel from "../components/AssetAnalysisPanel.vue";
import { api } from "../api";
import { enrollRepairDomain, fetchOpenWrtAdvisories, saveOpenWrtAdvisory } from "../api/deviceOperations";
import { controlSession } from "../api/controlSession";
import { notify, ui } from "../stores/ui";
import { ecosystemLabel, num, ratioPct } from "../utils/format";
import { formatBackendTime, timeAgoText } from "../utils/deviceCollection";
import VerdictRuling from "../components/VerdictRuling.vue";
import { ECOSYSTEM } from "../lib/palette";

const devices = ref([]);
const loading = ref(true);
const error = ref("");
const updated = ref("");
const eco = ref("all");
const view = ref("map");
const selected = ref(null);
const detailTab = ref("overview");
const analysisRefresh = ref(0);
const fileInput = ref(null);
const discoveryOpen = ref(false);
const cidr = ref("192.168.100.0/24");
const ports = ref("22, 80, 443");
const enroll = ref(true);
const discovering = ref(false);
const uploading = ref(false);

const domainOpen = ref(false);
const domainBusy = ref(false);
const domainChoice = ref("openwrt_lab");
const domainActor = ref("");
const domainReason = ref("");
const advisoryOpen = ref(false);
const advBusy = ref(false);
const advisories = ref([]);
const advForm = ref({ cve_id: "", package_name: "", release: "", affected: "", fixed: "", source_url: "", notes: "" });

const canEnrollRepairDomain = computed(() =>
  selected.value?.asset_id
  && selected.value.distribution === "openwrt"
  && (!selected.value.repair_domain || selected.value.repair_domain === "unassigned"));
const advValid = computed(() =>
  advForm.value.cve_id.trim().startsWith("CVE-")
  && advForm.value.package_name.trim()
  && advForm.value.release.trim()
  && (advForm.value.affected.trim() || advForm.value.fixed.trim())
  && advForm.value.source_url.trim().startsWith("http"));

function repairDomainLabel(value) {
  return { openwrt_lab: "OpenWrt 隔离实验", production: "生产设备", unassigned: "未登记" }[value] || value || "未登记";
}

function isNormalizedAdvisory(row) {
  try {
    const notes = typeof row.notes === "string" ? JSON.parse(row.notes) : row.notes || {};
    return notes?.provenance === "openwrt_ghsa_normalized";
  } catch {
    return false;
  }
}

async function submitRepairDomain() {
  if (!selected.value?.asset_id || !requireToken()) return;
  domainBusy.value = true;
  try {
    const result = await enrollRepairDomain(selected.value.asset_id, {
      domain: domainChoice.value,
      actor: domainActor.value.trim(),
      reason: domainReason.value.trim()
    });
    notify(`已登记授权域：${result.repair_domain}`, "success");
    domainOpen.value = false;
    domainActor.value = "";
    domainReason.value = "";
    await load();
  } catch (cause) {
    notify(cause?.response?.data?.detail || "授权域登记失败", "error");
  } finally {
    domainBusy.value = false;
  }
}

function openAdvisory() {
  if (!requireToken()) return;
  advisoryOpen.value = true;
  if (!advisories.value.length) loadAdvisories();
}

async function loadAdvisories() {
  try {
    advisories.value = await fetchOpenWrtAdvisories();
  } catch (cause) {
    notify(cause?.response?.data?.detail || "公告记录读取失败", "error");
  }
}

async function submitAdvisory() {
  if (!requireToken()) return;
  advBusy.value = true;
  try {
    const split = (value) => value.split(",").map((item) => item.trim()).filter(Boolean);
    await saveOpenWrtAdvisory({
      cve_id: advForm.value.cve_id.trim(),
      package_name: advForm.value.package_name.trim(),
      release: advForm.value.release.trim(),
      affected_versions: split(advForm.value.affected),
      fixed_versions: split(advForm.value.fixed),
      source_url: advForm.value.source_url.trim(),
      notes: advForm.value.notes.trim()
    });
    notify("版本记录已登记；请运行漏洞匹配使记录生效。", "success");
    advForm.value = { cve_id: "", package_name: "", release: "", affected: "", fixed: "", source_url: "", notes: "" };
    await loadAdvisories();
  } catch (cause) {
    notify(cause?.response?.data?.detail || "公告登记失败", "error");
  } finally {
    advBusy.value = false;
  }
}

const ecoCatalog = {
  openwrt: { icon: "router", color: ECOSYSTEM.openwrt.color, soft: ECOSYSTEM.openwrt.soft },
  zephyr: { icon: "cpu", color: ECOSYSTEM.zephyr.color, soft: ECOSYSTEM.zephyr.soft },
  ubuntu: { icon: "server", color: ECOSYSTEM.ubuntu.color, soft: ECOSYSTEM.ubuntu.soft },
  other_iot: { icon: "radio", color: ECOSYSTEM.other.color, soft: ECOSYSTEM.other.soft }
};

function ecoMeta(value) {
  return ecoCatalog[value] || ecoCatalog.other_iot;
}

const ecosystemCount = computed(() => new Set(devices.value.map((d) => d.ecosystem).filter(Boolean)).size);
const componentCount = computed(() => devices.value.reduce((sum, d) => sum + Number(d.component_count || 0), 0));
const trustedCount = computed(() => devices.value.filter((d) => Number(d.identity_confidence) >= 0.9).length);
const incompleteCount = computed(() => devices.value.filter((d) => d.inventory_complete === false).length);
const unidentifiedCount = computed(() => devices.value.filter((d) => !d.version || Number(d.identity_confidence) < 0.5).length);
const trustRate = computed(() => (devices.value.length ? `${Math.round((trustedCount.value / devices.value.length) * 100)}%` : ""));
const coverageDevices = computed(() => devices.value.slice(0, 4));

const confidenceBuckets = computed(() => {
  const total = Math.max(devices.value.length, 1);
  const trusted = devices.value.filter((d) => Number(d.identity_confidence) >= 0.9).length;
  const partial = devices.value.filter((d) => Number(d.identity_confidence) >= 0.35 && Number(d.identity_confidence) < 0.9).length;
  const low = devices.value.length - trusted - partial;
  return [
    { label: "可信 ≥ 90%", count: trusted, width: `${(trusted / total) * 100}%`, tone: "low" },
    { label: "部分 35–90%", count: partial, width: `${(partial / total) * 100}%`, tone: "warn" },
    { label: "低 / 未知", count: low, width: `${(low / total) * 100}%`, tone: "" }
  ];
});

const typeItems = computed(() => {
  const counts = devices.value.reduce((map, d) => {
    const key = d.ecosystem || "other_iot";
    map[key] = (map[key] || 0) + 1;
    return map;
  }, {});
  return ["openwrt", "zephyr", "ubuntu", "other_iot"].map((key) => ({
    value: key,
    label: ecosystemLabel(key),
    count: counts[key] || 0,
    ...ecoMeta(key)
  }));
});

const filteredDevices = computed(() => {
  if (eco.value === "all") return devices.value;
  return devices.value.filter((d) => (d.ecosystem || "other_iot") === eco.value);
});

const recentDevices = computed(() =>
  [...devices.value]
    .sort((a, b) => new Date(b.inventory_collected_at || 0) - new Date(a.inventory_collected_at || 0))
    .slice(0, 5)
);

const topologyNodes = computed(() => {
  const counts = devices.value.reduce((map, d) => {
    const key = d.ecosystem || "other_iot";
    map[key] = (map[key] || 0) + 1;
    return map;
  }, {});
  return [
    { key: "openwrt", name: "OpenWrt", count: counts.openwrt || 0, ...ecoMeta("openwrt") },
    { key: "zephyr", name: "Zephyr", count: counts.zephyr || 0, ...ecoMeta("zephyr") },
    { key: "ubuntu", name: "Ubuntu", count: counts.ubuntu || 0, ...ecoMeta("ubuntu") },
    { key: "other", name: "其他 IoT", count: counts.other_iot || 0, ...ecoMeta("other_iot") }
  ];
});

function setEco(value) {
  eco.value = value;
  if (value !== "all") view.value = "list";
}

function openDetail(device) {
  selected.value = device;
  detailTab.value = "overview";
}

async function onCollectionUpdated() {
  const key = selected.value?.key;
  await load();
  if (!key) return;
  const fresh = devices.value.find((device) => device.key === key);
  if (fresh) selected.value = { ...selected.value, ...fresh };
  analysisRefresh.value += 1;
}

function onAnalysisStarted(round) {
  if (round?.round_id) {
    notify(`分析轮次 ${round.round_id} 已启动：候选 ${round.counts?.candidates ?? 0} 条，本轮选择 ${round.counts?.selected ?? 0} 条`, "success");
  }
}

function ecoClass(value) {
  return { openwrt: "accent", zephyr: "low", ubuntu: "info" }[value] || "muted";
}
function identityTone(value) {
  const n = Number(value);
  return n >= 0.9 ? "low" : n >= 0.35 ? "high" : "muted";
}
function runtimeLabel(value) {
  return { requires_sensor_evidence: "需传感器证据", ebpf_not_applicable: "RTOS 不支持 eBPF", requires_runtime_evidence: "需运行时证据" }[value] || value || "未记录";
}
function remediationLabel(value) {
  return { requires_device_specific_plan: "需设备专用方案", firmware_update_not_automated: "固件更新未接通" }[value] || value || "—";
}
function nextActionLabel(value) {
  return {
    review_applicability: "复核漏洞适用性",
    collect_inventory: "补采资产清单",
    schedule_repair: "排期修复",
    monitor: "持续观察"
  }[value] || value || "—";
}
function assessmentLabel(value) {
  return { partial: "部分评估", unassessed: "未评估", complete: "已评估", evaluated: "已评估" }[value] || value || "未记录";
}
function assessmentClass(value) {
  if (value === "complete" || value === "evaluated") return "low";
  if (value === "partial") return "warn";
  return "";
}
function assessmentWidth(value) {
  return { partial: "66%", complete: "100%", evaluated: "100%", unassessed: "0%" }[value] || "0%";
}
function pctClass(value) {
  const n = Number(value);
  return n >= 0.9 ? "low" : n >= 0.35 ? "warn" : "";
}

function exportCsv() {
  const rows = [["key", "name", "ecosystem", "version", "component_count", "identity_confidence", "inventory_complete"]];
  for (const d of devices.value) rows.push([d.key, d.name, d.ecosystem, d.version, d.component_count, d.identity_confidence, d.inventory_complete]);
  const csv = rows.map((row) => row.map((value) => `"${String(value ?? "").replaceAll('"', '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "iotguard-assets.csv";
  link.click();
  URL.revokeObjectURL(url);
}

function requireToken() {
  if (controlSession.token) return true;
  notify("请先在顶栏设置操作令牌", "error");
  ui.tokenOpen = true;
  return false;
}

function pickImport() {
  if (!requireToken()) return;
  fileInput.value?.click();
}

async function importAsset(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  uploading.value = true;
  try {
    const form = new FormData();
    form.append("file", file);
    await api.post("/assets/upload", form, {
      headers: { "X-Control-Token": controlSession.token },
      timeout: 120000
    });
    notify(`已导入 ${file.name}`, "success");
    await load();
  } catch (cause) {
    notify(cause?.response?.data?.detail || "清单导入失败", "error");
  } finally {
    uploading.value = false;
    if (fileInput.value) fileInput.value.value = "";
  }
}

function openDiscovery() {
  if (!requireToken()) return;
  discoveryOpen.value = true;
}

async function submitDiscovery() {
  discovering.value = true;
  try {
    const portList = ports.value.split(",").map((value) => Number(value.trim())).filter((value) => Number.isInteger(value) && value > 0 && value < 65536);
    const result = await api.post(
      "/iot/discovery",
      { cidr: cidr.value.trim(), ports: portList, enroll: enroll.value },
      { headers: { "X-Control-Token": controlSession.token }, timeout: 180000 }
    );
    const count = Array.isArray(result.data) ? result.data.length : result.data?.count;
    notify(`发现请求已完成${count !== undefined ? ` · ${count} 条观测` : ""}`, "success");
    discoveryOpen.value = false;
    await load();
  } catch (cause) {
    notify(cause?.response?.data?.detail || "发现失败", "error");
  } finally {
    discovering.value = false;
  }
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const [overview, inventory] = await Promise.allSettled([
      api.get("/devices/business/overview", { timeout: 25000 }),
      api.get("/assets", { timeout: 25000 })
    ]);
    const base = overview.status === "fulfilled" && Array.isArray(overview.value.data?.devices) ? overview.value.data.devices : [];
    const meta = new Map();
    if (inventory.status === "fulfilled" && Array.isArray(inventory.value.data)) {
      for (const asset of inventory.value.data) meta.set(`asset:${asset.id}`, asset);
    }
    devices.value = base.map((device) => {
      const extra = meta.get(device.key) || {};
      const keyedId = typeof device.key === "string" && device.key.startsWith("asset:") ? Number(device.key.slice(6)) : null;
      return {
        ...device,
        asset_id: Number.isFinite(keyedId) && keyedId > 0 ? keyedId : null,
        distribution: extra.distribution || (device.ecosystem === "openwrt" ? "openwrt" : ""),
        identity_source: extra.identity_source || "",
        ip_address: extra.ip_address || "",
        inventory_collected_at: extra.inventory_collected_at || "",
        os_name: extra.os_name || "",
        repair_domain: extra.repair_domain || "unassigned",
        repair_domain_actor: extra.repair_domain_actor || "",
        repair_domain_reason: extra.repair_domain_reason || ""
      };
    });
    updated.value = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  } catch (cause) {
    error.value = cause?.response?.data?.detail || "资产台账读取失败，请检查后端服务。";
  } finally {
    loading.value = false;
  }
}

watch(selected, (value) => {
  if (!value) detailTab.value = "overview";
});


/* 页面级状态印章：资产页回答"清单可信到什么程度" */
const ruling = computed(() => {
  const total = devices.value.length;
  const trusted = trustedCount.value;
  const incomplete = incompleteCount.value;
  const unknown = unidentifiedCount.value;
  const tags = [
    { text: `设备 ${total} 台`, tone: "" },
    { text: `身份可信 ${trusted}`, tone: trusted === total && total > 0 ? "low" : "mid" },
    { text: `清单待补 ${incomplete}`, tone: incomplete > 0 ? "high" : "" },
    { text: `未识别 ${unknown}`, tone: unknown > 0 ? "mid" : "" },
  ];
  if (total === 0) {
    return {
      state: "weak", stampMain: "无数据", stampEn: "NO DATA",
      title: "当前没有已发现设备",
      detail: "没有设备不代表网络干净：需要先完成采集或导入清单，资产盘点才有意义。",
      tags,
    };
  }
  if (incomplete > 0 || unknown > 0) {
    return {
      state: "weak", stampMain: "清单不全", stampEn: "INCOMPLETE",
      title: `${total} 台设备中，${incomplete} 台清单待补、${unknown} 台未识别`,
      detail: "清单缺失会让漏洞匹配失去依据；未识别设备不能假定为安全。",
      tags,
    };
  }
  return {
    state: "pass", stampMain: "清单可用", stampEn: "READY",
    title: `${total} 台设备清单完整，身份可信 ${trusted} 台`,
    detail: "该结论仅覆盖已发现设备；未接入的网段不在统计范围内。",
    tags,
  };
});
onMounted(load);
</script>

<style scoped>
.asset-grid { display: grid; grid-template-columns: 236px minmax(0, 1fr) 286px; gap: 16px; align-items: stretch; }
.detail-tabs { justify-self: start; }
.detail-tabs span { cursor: pointer; }
.domain-note { display: block; margin-top: 4px; color: var(--muted); font-size: 12.5px; font-weight: 400; }
.enroll-link { margin-top: 4px; font-size: 13.5px; }
.plan-rows-mini { display: grid; gap: 4px; padding: 8px 12px; margin-bottom: 12px; border: 1px solid var(--line-soft); border-radius: 10px; background: #f9fbfe; }
.plan-rows-mini div { display: grid; grid-template-columns: 92px minmax(0, 1fr); gap: 8px; font-size: 14px; }
.plan-rows-mini span { color: var(--muted); }
.plan-rows-mini b { color: var(--ink-2); font-weight: 600; }
.adv-grid { display: grid; grid-template-columns: minmax(0, 1.05fr) minmax(0, 1fr); gap: 16px; }
.adv-form { display: grid; gap: 4px; align-content: start; }
.adv-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 8px; }
.adv-list { border: 1px solid var(--line-soft); border-radius: 12px; background: #fbfdff; max-height: 460px; overflow: auto; }
.adv-list-head { padding: 8px 12px; border-bottom: 1px solid var(--line-soft); color: var(--ink); font-size: 14px; font-weight: 700; position: sticky; top: 0; background: #fbfdff; }
.adv-row { padding: 8px 12px; border-bottom: 1px solid var(--line-soft); font-size: 13.5px; }
.adv-row.exact { background: #f2fbf5; }
.adv-row-top { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.adv-row-top b { color: var(--ink); font-size: 13.5px; }
.adv-row-line { color: var(--muted); margin-top: 2px; overflow: hidden; text-overflow: ellipsis; }
@media (max-width: 960px) { .adv-grid { grid-template-columns: minmax(0, 1fr); } }
.type-card, .recent-card { display: flex; flex-direction: column; }
.type-list { display: grid; gap: 2px; padding: 8px 8px 4px; }
.type-row {
  display: flex;
  align-items: center;
  gap: 8px;
  height: 46px;
  padding: 0 10px;
  border: 0;
  border-radius: 9px;
  background: transparent;
  color: var(--ink-2);
  text-align: left;
  transition: background 140ms ease;
}
.type-row:hover { background: #f7fafd; }
.type-row.active { background: #eff5ff; box-shadow: inset 0 0 0 1px #d8e6ff; }
.type-ic { display: grid; place-items: center; width: 28px; height: 28px; border-radius: 8px; flex: 0 0 auto; }
.type-name { flex: 1; font-size: 14px; font-weight: 600; color: #33465e; }
.type-row.active .type-name { color: #1d4ed8; }
.type-row b { color: var(--ink); font-size: 14px; font-weight: 700; }
.type-chev { color: #c3d1e3; }
.type-row.active .type-chev { color: #2f6fed; }
.type-foot { margin-top: 0; padding: 8px 16px 12px; border-top: 1px solid var(--line-soft); color: var(--muted); font-size: 12.5px; line-height: 1.5; }
.type-sep { margin-top: auto; display: grid; gap: 8px; padding: 12px 16px 12px; border-top: 1px solid var(--line-soft); }
.type-sep-title { color: var(--ink); font-size: 14px; font-weight: 700; }
.bucket-row { display: grid; grid-template-columns: 86px minmax(0, 1fr) 24px; gap: 8px; align-items: center; color: var(--muted); font-size: 12.5px; }
.bucket-track { height: 6px; border-radius: 999px; background: #eef3fa; overflow: hidden; }
.bucket-track i { display: block; height: 6px; border-radius: 999px; background: #c3d1e3; }
.bucket-track i.low { background: var(--low); }
.bucket-track i.warn { background: var(--high); }
.bucket-row b { text-align: right; color: var(--ink-2); font-size: 13.5px; font-weight: 700; }

.map-card { display: flex; flex-direction: column; }
.map-body { padding: 8px 14px 0; }
.map-legend { display: flex; align-items: center; gap: 16px; padding: 2px 4px 4px; color: #64748b; font-size: 13.5px; }
.map-legend span { display: inline-flex; align-items: center; gap: 4px; }
.map-legend b { color: var(--ink); font-family: var(--font-num); font-weight: 700; }
.map-list { max-height: 440px; }
.map-foot { display: flex; align-items: center; justify-content: space-between; padding: 8px 4px 8px; border-top: 1px solid var(--line-soft); margin-top: 4px; color: var(--muted); font-size: 12.5px; }

.recent-list { display: grid; padding: 4px 8px; }
.recent-row {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 8px 8px;
  border: 0;
  border-radius: 10px;
  background: transparent;
  text-align: left;
}
.recent-row:hover { background: #f7fafd; }
.recent-ic { display: grid; place-items: center; width: 34px; height: 34px; border-radius: 9px; flex: 0 0 auto; }
.recent-copy { min-width: 0; flex: 1; display: grid; gap: 2px; }
.recent-copy b { color: var(--ink); font-size: 14px; font-weight: 650; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.recent-copy small { color: var(--muted); font-family: var(--font-num); font-size: 12.5px; }
.recent-time { color: #64748b; font-size: 12.5px; white-space: nowrap; }
.recent-chev { color: #c3d1e3; }
.recent-foot { margin-top: auto; display: flex; align-items: center; gap: 8px; padding: 8px 16px; border-top: 1px solid var(--line-soft); color: var(--muted); font-size: 12.5px; }
.recent-foot .dot { background: var(--low); }
</style>
