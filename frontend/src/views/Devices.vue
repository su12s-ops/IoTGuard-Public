<template>
  <div class="page">
    <PageHeader
      title="设备接入"
      subtitle="DEVICE ONBOARDING"
      description="真实设备 → 协议探测 → 身份识别 → 台账快照；页面上每个字段都能回到设备返回的原始响应。"
    >
      <template #meta>
        <span class="mono d-key">{{ hasData ? device.device_key : "尚无采集记录" }}</span>
        <span class="d-dot">·</span>
        <span>{{ capturedLabel }}</span>
      </template>
      <template #actions>
        <button class="btn" type="button" @click="printView"><Icon name="printer" :size="15" />打印</button>
        <button class="btn" :class="{ primary: !liveOn }" type="button" :disabled="probing" @click="probeLive">
          <Icon name="refresh" :size="15" />{{ probing ? "现场实测中…" : "现场实测" }}
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

    <section class="card d-channel d-rise" style="--d: 0ms">
      <div class="d-channel-row">
        <span class="chip info"><i class="dot" />⟲ 冻结快照 · {{ hasData ? capturedLabel : "无" }}</span>
        <span class="chip" :class="liveOn ? 'low' : bridgeUp ? 'info' : 'muted'">
          <i class="dot" />{{ liveOn ? "▶ 现场实测 · 可用" : bridgeUp ? "▶ 现场实测 · 就绪" : "▶ 现场实测 · 未连接" }}
        </span>
        <span class="chip" :class="selfCheckTone">
          <i class="dot" />{{ selfCheckLabel }}
        </span>
        <span class="d-channel-note">
          {{ liveOn
            ? `实测来源 ${livePidLabel} · ${live.serverTime}`
            : bridgeUp
              ? "本地桥 127.0.0.1:8901 在线；点「现场实测」会重新探测设备，并与冻结快照逐字段对照。"
              : "本地桥 127.0.0.1:8901 未启动时，本页只呈现冻结快照，并把未复核的部分直接写明。" }}
        </span>
      </div>
      <p v-if="liveError" class="d-live-error" role="status">
        <Icon name="alert" :size="14" />{{ liveError }}
      </p>
    </section>

    <section v-if="!hasData" class="card d-empty d-rise" style="--d: 40ms">
      <h2 class="card-title">尚未接入设备</h2>
      <p class="d-empty-copy">
        快照文件里没有设备记录（当前是占位件）。在 <span class="mono">E:\竞赛\强网杯\IoTGuard-Public-main-new</span>
        下执行下面这条命令，会拉起仓库自带的 SmartCam-X1 设备、真实探测四个服务、与设备自报身份逐字段核对，然后覆盖本页数据：
      </p>
      <pre class="d-cmd mono">python _work/device_capture.py --selftest</pre>
      <p class="d-empty-copy">
        对已在线的真实设备采集（不拉模拟器）：
      </p>
      <pre class="d-cmd mono">python _work/device_capture.py --no-start --host 192.168.100.1 --ports 22,80,443,1883,554</pre>
      <p class="d-empty-foot">页面不臆造设备；没有采集结果就保持空白并给出可执行的下一步。</p>
    </section>

    <template v-else>
      <section class="card d-hero d-rise" style="--d: 40ms">
        <div class="d-hero-left">
          <span class="d-badge"><Icon name="camera" :size="26" /></span>
          <div class="d-hero-copy">
            <h2 class="d-hero-name">{{ device.device_name }}</h2>
            <p class="d-hero-sub">{{ device.vendor || "厂商未识别" }} · {{ device.model || "型号未识别" }}</p>
            <p class="d-hero-tags">
              <span class="chip" :class="onlineTone"><i class="dot" />{{ device.status === "online" ? "在线" : "离线" }}</span>
              <span class="chip muted"><i class="dot" />{{ sourceLabel(device.identity_source) }}</span>
              <span class="chip info"><i class="dot" />身份可信 {{ confidencePct(device.identity_confidence) }}</span>
              <span class="chip mid"><i class="dot" />漏洞评估未执行</span>
            </p>
          </div>
        </div>
        <dl class="d-readouts">
          <div>
            <dt>固件版本</dt>
            <dd class="d-readout mono">{{ device.firmware_version || "未识别" }}</dd>
          </div>
          <div>
            <dt>开放服务</dt>
            <dd class="d-readout mono">{{ services.length }}</dd>
          </div>
          <div>
            <dt>暴露面基线</dt>
            <dd class="d-readout mono" :class="'tone-' + exposureTone(exposure ? exposure.score : null)">
              {{ exposure && exposure.score !== undefined ? exposure.score : "—" }}
            </dd>
          </div>
        </dl>
      </section>

      <section class="card d-fields d-rise" style="--d: 80ms">
        <div class="card-head">
          <div>
            <h2 class="card-title">身份字段</h2>
            <div class="card-desc">字段来源是设备的只读身份端点；未识别的字段留空，不用默认值填空。</div>
          </div>
          <span class="chip muted">台账键 <b class="mono">{{ device.device_key }}</b></span>
        </div>
        <div class="card-body d-field-grid">
          <div v-for="row in identityFields" :key="row.label" class="d-field">
            <span>{{ row.label }}</span>
            <b :class="row.mono ? 'mono' : ''">{{ row.value }}</b>
          </div>
        </div>
      </section>

      <section class="card d-services d-rise" style="--d: 120ms">
        <div class="card-head">
          <div>
            <h2 class="card-title">服务暴露面</h2>
            <div class="card-desc">每个端口都按真实协议交互识别（SSH 横幅 / HTTP 响应 / MQTT CONNACK / RTSP OPTIONS），点行看原始证据。</div>
          </div>
          <span class="chip muted">探测端口 {{ portSetText(services) }}</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">端口</th>
                <th scope="col">协议</th>
                <th scope="col">产品</th>
                <th scope="col">版本</th>
                <th scope="col">认证态</th>
                <th scope="col">原始响应</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="svc in services"
                :key="'svc-' + svc.port"
                tabindex="0"
                role="button"
                :aria-label="`查看 ${svc.port} 端口证据`"
                style="cursor: pointer"
                @click="openEvidence(svc)"
                @keydown.enter="openEvidence(svc)"
              >
                <td class="mono">{{ svc.port }}</td>
                <td><span class="chip" :class="serviceTone(svc.service_type)"><i class="dot" />{{ serviceLabel(svc.service_type) }}</span></td>
                <td>{{ svc.product || "未识别" }}</td>
                <td class="mono">{{ svc.version || "—" }}</td>
                <td><span class="chip" :class="authTone(svc.auth_state)"><i class="dot" />{{ authLabel(svc.auth_state) }}</span></td>
                <td class="d-banner mono" :title="svc.banner">{{ svc.banner || "无横幅" }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-if="exposure && exposure.anonymous_mqtt" class="d-warn" role="note">
          <Icon name="shield-alert" :size="15" />
          <span>MQTT 接受匿名接入：探测报文拿到了 CONNACK 返回码 0，未提交任何凭据。这是设备事实，不是推测。</span>
        </div>
      </section>

      <div class="d-two">
        <section class="card d-components d-rise" style="--d: 160ms">
          <div class="card-head">
            <div>
              <h2 class="card-title">组件清单</h2>
              <div class="card-desc">固件取设备自报，软件取服务横幅；来源不同的组件不合并。</div>
            </div>
            <span class="chip muted">{{ components.length }} 个</span>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr><th scope="col">组件</th><th scope="col">类型</th><th scope="col">版本</th><th scope="col">来源</th></tr>
              </thead>
              <tbody>
                <tr v-for="item in components" :key="'cmp-' + item.component_name">
                  <td>
                    {{ item.component_name }}
                    <div v-if="item.cpe" class="mono d-cpe">{{ item.cpe }}</div>
                  </td>
                  <td>{{ componentTypeLabel(item.component_type) }}</td>
                  <td class="mono">{{ item.version || "—" }}</td>
                  <td>{{ componentSourceLabel(item.source) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section class="card d-exposure d-rise" style="--d: 200ms">
          <div class="card-head">
            <div>
              <h2 class="card-title">暴露面构成</h2>
              <div class="card-desc">只按已识别服务的开放程度计分，不预测可利用性。</div>
            </div>
          </div>
          <div class="card-body">
            <div class="d-score">
              <b class="mono" :class="'tone-' + exposureTone(exposure ? exposure.score : null)">
                {{ exposure && exposure.score !== undefined ? exposure.score : "—" }}
              </b>
              <span>/ 40 上限</span>
            </div>
            <ul v-if="exposure && exposure.factors" class="d-factors">
              <li v-for="(value, key) in exposure.factors" :key="'f-' + key">
                <span class="mono">{{ factorLabel(key) }}</span>
                <b class="mono">+{{ value }}</b>
              </li>
            </ul>
            <p class="d-note">
              设备级 CVE 匹配（security_status={{ device.security_status || "unknown" }}）没有在本快照执行：
              本页不给「安全」结论，只给可复核的暴露事实。
            </p>
          </div>
        </section>
      </div>

      <section v-if="liveOn" class="card d-compare d-rise" style="--d: 240ms">
        <div class="card-head">
          <div>
            <h2 class="card-title">快照 ↔ 现场实测：逐字段对照</h2>
            <div class="card-desc">每次点「现场实测」都重新探测一次设备；不一致就标出来，不覆盖快照。</div>
          </div>
          <span class="chip" :class="diff.diffCount ? 'high' : diff.unverifiedCount ? 'mid' : 'low'">
            <i class="dot" />差异 {{ diff.diffCount }} · 未复核 {{ diff.unverifiedCount }}
          </span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th scope="col">字段</th><th scope="col">冻结快照</th><th scope="col">现场实测</th><th scope="col">状态</th></tr>
            </thead>
            <tbody>
              <tr v-for="row in diff.rows" :key="'c-' + row.key">
                <td>{{ row.label }}</td>
                <td class="mono">{{ row.left }}</td>
                <td class="mono">{{ row.right }}</td>
                <td>
                  <span class="chip" :class="row.state === 'same' ? 'low' : row.state === 'diff' ? 'crit' : 'muted'">
                    <i class="dot" />{{ row.state === "same" ? "一致" : row.state === "diff" ? "不一致" : "未复核" }}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="card d-chain d-rise" style="--d: 280ms">
        <div class="card-head">
          <div>
            <h2 class="card-title">采集链路与自检</h2>
            <div class="card-desc">探测与识别调用仓库原文件，本页只做序列化；指纹可当场复算。</div>
          </div>
          <button class="btn" type="button" @click="openProvenance">
            <Icon name="terminal" :size="15" />查看采集记录
          </button>
        </div>
        <div class="card-body d-chain-grid">
          <div v-for="row in chainRows" :key="row.label" class="d-chain-item">
            <span>{{ row.label }}</span>
            <b :class="row.mono ? 'mono' : ''">{{ row.value }}</b>
          </div>
        </div>
        <div class="d-selfcheck" :class="selfCheckOk ? 'ok' : 'bad'">
          <Icon :name="selfCheckOk ? 'check-circle' : 'alert'" :size="16" />
          <div>
            <b>{{ selfCheckLabel }}</b>
            <p v-if="selfCheck && selfCheck.ok">
              以设备自报身份端点 {{ selfCheck.endpoint || "—" }} 为基准，逐项比对
              {{ (selfCheck.compared_fields || []).length }} 个字段，无差异。
            </p>
            <ul v-else-if="selfCheck && (selfCheck.mismatches || []).length">
              <li v-for="item in selfCheck.mismatches" :key="item">{{ item }}</li>
            </ul>
            <p v-else>没有自检记录：无法用设备自报作比对基准，本页按「未复核」处理。</p>
          </div>
        </div>
      </section>
    </template>

    <Modal
      :open="Boolean(evidence)"
      :title="evidence ? `${evidence.port} · ${serviceLabel(evidence.service_type)} 原始证据` : '原始证据'"
      description="设备返回的原始响应，按识别器解析后的结构保存；不做二次加工。"
      wide
      @close="evidence = null"
    >
      <pre v-if="evidence" class="d-json mono">{{ JSON.stringify(evidence, null, 2) }}</pre>
      <template #footer>
        <button class="btn" type="button" @click="evidence = null">关闭</button>
      </template>
    </Modal>

    <Modal
      :open="provenanceOpen"
      title="采集记录"
      description="这次快照是怎么来的：工具、模块指纹、端口耗时与快照指纹。"
      wide
      @close="provenanceOpen = false"
    >
      <pre class="d-json mono">{{ JSON.stringify(provenanceView, null, 2) }}</pre>
      <template #footer>
        <button class="btn" type="button" @click="provenanceOpen = false">关闭</button>
      </template>
    </Modal>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import PageHeader from "../components/PageHeader.vue";
import VerdictRuling from "../components/VerdictRuling.vue";
import Icon from "../components/Icon.vue";
import Modal from "../components/Modal.vue";
import dataFile from "../data/devices-data.json";
import {
  authLabel,
  authTone,
  compare,
  componentSourceLabel,
  componentTypeLabel,
  confidencePct,
  exposureTone,
  hasDevice,
  msLabel,
  normalize,
  portSetText,
  serviceLabel,
  shortHash,
  sourceLabel
} from "../lib/deviceInventory";

const BRIDGE = import.meta.env.VITE_DEVICE_BRIDGE || "http://127.0.0.1:8901";

const snapshot = normalize(dataFile);
const hasData = computed(() => hasDevice(dataFile));
const device = computed(() => snapshot.device || {});
const services = computed(() => snapshot.services);
const components = computed(() => snapshot.components);
const exposure = computed(() => snapshot.exposure);
const selfCheck = computed(() => snapshot.selfCheck);

const live = ref(null);
const liveError = ref("");
const probing = ref(false);
const bridgeUp = ref(false);
const evidence = ref(null);
const provenanceOpen = ref(false);

const liveOn = computed(() => Boolean(live.value));
const selfCheckOk = computed(() => Boolean(selfCheck.value && selfCheck.value.ok));

/* 页面级状态印章：设备接入页回答"这台设备现在处于什么状态" */
const ruling = computed(() => {
  const info = device.value || {};
  const svc = Array.isArray(services.value) ? services.value.length : 0;
  const comp = Array.isArray(components.value) ? components.value.length : 0;
  const tags = [
    { text: `服务 ${svc}`, tone: "" },
    { text: `组件 ${comp}`, tone: "" },
    { text: selfCheckOk.value ? "自检通过" : "自检未通过", tone: selfCheckOk.value ? "low" : "mid" },
    { text: liveOn.value ? "现场实测已取" : "未现场实测", tone: liveOn.value ? "low" : "" },
  ];
  if (!hasData.value) {
    return {
      state: "weak", stampMain: "未接入", stampEn: "NOT ONBOARDED",
      title: "当前没有设备快照",
      detail: "设备接入需要真实协议交互：识别身份、读取清单、回填台账，三个阶段缺一不可。",
      tags,
    };
  }
  if (!selfCheckOk.value) {
    return {
      state: "weak", stampMain: "自检未过", stampEn: "SELF-CHECK FAILED",
      title: `${info.device_name || "该设备"} 的自检未通过`,
      detail: "字段来源与协议回执对不上时，台账数据不可作为凭证；未复核不应进入风险库。",
      tags,
    };
  }
  return {
    state: "pass", stampMain: "已接入", stampEn: "ONBOARDED",
    title: `${info.device_name || "该设备"} 已完成接入与自检`,
    detail: `固件 ${info.firmware_version || "未登记"}；结论覆盖 ${svc} 个服务与 ${comp} 个组件。`,
    tags,
  };
});
const selfCheckTone = computed(() => (selfCheck.value ? (selfCheckOk.value ? "low" : "crit") : "muted"));
const selfCheckLabel = computed(() => {
  if (!selfCheck.value) return "自检 · 无记录";
  return selfCheckOk.value ? "自检 · 通过" : "自检 · 不通过";
});
const onlineTone = computed(() => (device.value.status === "online" ? "low" : "muted"));
const livePidLabel = computed(() => {
  if (!live.value) return "未连接";
  return `请求 ${shortHash(live.value.reqId, 6)} · pid ${live.value.pid} · ${msLabel(live.value.elapsedMs)}`;
});

const capturedLabel = computed(() => {
  if (!snapshot.capturedAt) return "未采集";
  const time = new Date(snapshot.capturedAt);
  if (Number.isNaN(time.getTime())) return snapshot.capturedAt;
  return time.toLocaleString("zh-CN", { hour12: false });
});

const identityFields = computed(() => [
  { label: "设备类型", value: device.value.device_type || "未识别", mono: true },
  { label: "系统", value: device.value.os || "未识别", mono: true },
  { label: "管理地址", value: device.value.ip || "未记录", mono: true },
  { label: "MAC / 序列号", value: identityMeta(), mono: true },
  { label: "身份来源", value: sourceLabel(device.value.identity_source) },
  { label: "身份可信度", value: confidencePct(device.value.identity_confidence) },
  { label: "风险评估", value: device.value.risk_score_basis || "未评估", mono: true },
  { label: "采集时间", value: capturedLabel.value, mono: true }
]);

const chainRows = computed(() => {
  const prov = snapshot.provenance || {};
  return [
    { label: "采集工具", value: prov.capture_tool || "—", mono: true },
    { label: "识别模块", value: `${prov.backend_module || "—"} · ${shortHash(prov.backend_module_sha256, 8)}`, mono: true },
    { label: "设备源码", value: `${prov.simulator_device || "—"} · ${shortHash(prov.simulator_sha256, 8)}`, mono: true },
    { label: "Python", value: prov.python || "—", mono: true },
    { label: "探测端口", value: (prov.probe_ports || []).join(" / ") || "—", mono: true },
    { label: "总耗时", value: msLabel(prov.elapsed_ms) },
    { label: "逐端口耗时", value: perPortText(prov.per_port_ms), mono: true },
    { label: "快照指纹", value: shortHash(snapshot.snapshotSha, 10), mono: true }
  ];
});

const provenanceView = computed(() => ({
  快照: {
    schema: dataFile.schema,
    captured_at: snapshot.capturedAt,
    snapshot_sha256: snapshot.snapshotSha || "未记录",
    复算命令: dataFile.verify_command || "python _work/device_capture.py --verify-hash"
  },
  采集: snapshot.provenance || {},
  自检: selfCheck.value || {},
  现场实测: live.value
    ? { req_id: live.value.reqId, pid: live.value.pid, server_time: live.value.serverTime, elapsed_ms: live.value.elapsedMs }
    : "未连接本地桥"
}));

const diff = computed(() => (live.value ? compare(snapshot, normalize(live.value)) : { rows: [], diffCount: 0, unverifiedCount: 0 }));

function identityMeta() {
  const meta = device.value.identity_metadata || {};
  const parts = [meta.mac_address, meta.serial_number].filter(Boolean);
  return parts.length ? parts.join(" · ") : "未记录";
}

function perPortText(map) {
  if (!map || typeof map !== "object") return "—";
  return Object.entries(map).map(([port, ms]) => `${port}:${ms}`).join(" ");
}

function factorLabel(key) {
  return {
    "port_service:ssh": "SSH 开放",
    "port_service:http": "HTTP 开放",
    "port_service:https": "HTTPS 开放",
    "port_service:mqtt": "MQTT 开放",
    "port_service:rtsp": "RTSP 开放",
    mqtt_anonymous_access: "MQTT 匿名接入"
  }[key] || key;
}

function serviceTone(type) {
  return { ssh: "info", http: "info", https: "info", mqtt: "high", rtsp: "accent", unknown: "muted" }[type] || "muted";
}

function openEvidence(svc) {
  evidence.value = {
    port: svc.port,
    service_type: svc.service_type,
    transport: svc.transport,
    product: svc.product,
    version: svc.version,
    auth_state: svc.auth_state,
    banner: svc.banner,
    evidence: svc.evidence || {}
  };
}

function openProvenance() {
  provenanceOpen.value = true;
}

function printView() {
  window.print();
}

async function fetchJson(url, timeoutMs) {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal, headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally {
    window.clearTimeout(timer);
  }
}

async function probeLive() {
  if (probing.value) return;
  probing.value = true;
  liveError.value = "";
  try {
    const payload = await fetchJson(`${BRIDGE}/api/devices/live`, 20000);
    live.value = normalize(payload);
    bridgeUp.value = true;
  } catch (cause) {
    live.value = null;
    bridgeUp.value = false;
    liveError.value = `现场实测不可用：${cause && cause.name === "AbortError" ? "探测超时（20s）" : cause.message}。先运行 python _work/device_bridge.py --ensure-device，本页仍以冻结快照为准。`;
  } finally {
    probing.value = false;
  }
}

async function checkBridge() {
  try {
    // 4s：机器繁忙时 1.8s 会误判"未连接"，而通道条一旦误判就是在说假话。
    const health = await fetchJson(`${BRIDGE}/api/health`, 4000);
    bridgeUp.value = Boolean(health && health.ok);
  } catch {
    bridgeUp.value = false;
  }
}

onMounted(() => {
  if (hasData.value) checkBridge();
});
</script>

<style scoped>
.page { display: grid; gap: 12px; }

/* 字号统一走全站字阶（styles/redesign/tokens.css 的 --fs-*）：投影可读下限 13px。
   本页不再自带一套 px 字阶，只有表头颜色在这里校正到 4.5:1。 */
.page :deep(th) { color: var(--ink-3); font-size: var(--fs-micro); }

.d-cpe { margin-top: 2px; color: var(--ink-3); font-size: var(--fs-micro); overflow-wrap: anywhere; }
.d-key { letter-spacing: -0.02em; }
.d-dot { padding: 0 2px; }

.d-channel { padding: 12px 16px; }
.d-channel-row { display: flex; align-items: center; flex-wrap: wrap; gap: 8px 8px; }
.d-channel-note { color: var(--ink-3); font-size: var(--fs-micro); }
.d-live-error {
  display: flex; align-items: center; gap: 8px; margin: 8px 0 0;
  color: var(--crit); font-size: var(--fs-meta);
}

.d-empty { padding: 16px 16px; display: grid; gap: 8px; }
.d-empty-copy { color: var(--ink-2); font-size: var(--fs-body); line-height: 1.6; max-width: 88ch; }
.d-cmd {
  margin: 0; padding: 8px 12px; border-radius: var(--radius-sm);
  background: var(--surface-2); border: 1px solid var(--line);
  color: var(--ink); font-size: var(--fs-meta); overflow-x: auto;
}
.d-empty-foot { color: var(--ink-3); font-size: var(--fs-micro); }

.d-hero { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 16px; }
.d-hero-left { display: flex; align-items: center; gap: 12px; min-width: 0; }
.d-badge {
  display: grid; place-items: center; width: 52px; height: 52px; flex: 0 0 auto;
  border-radius: 14px; background: var(--accent-soft); color: var(--accent);
}
.d-hero-copy { min-width: 0; }
.d-hero-name { font-size: var(--fs-head); font-weight: 700; letter-spacing: -0.02em; color: var(--ink); }
.d-hero-sub { margin-top: 2px; color: var(--ink-3); font-size: var(--fs-meta); }
.d-hero-tags { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 8px; }
.d-readouts { display: flex; gap: 24px; margin: 0; }
.d-readouts dt { color: var(--ink-3); font-size: var(--fs-micro); }
.d-readout { margin: 2px 0 0; font-size: var(--fs-number); font-weight: 700; line-height: 1; letter-spacing: -0.03em; color: var(--ink); }
.d-readout.tone-crit { color: var(--crit); }
.d-readout.tone-high { color: var(--high); }
.d-readout.tone-mid { color: var(--mid); }
.d-readout.tone-low { color: var(--low); }

.d-fields .d-field-grid {
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px 16px;
}
.d-field { display: grid; gap: 2px; min-width: 0; }
.d-field span { color: var(--ink-3); font-size: var(--fs-micro); }
.d-field b { color: var(--ink); font-size: var(--fs-body); font-weight: 600; overflow-wrap: anywhere; }

.d-banner { max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink-2); }
.d-warn {
  display: flex; align-items: flex-start; gap: 8px; margin: 12px 16px 4px;
  padding: 8px 12px; border-radius: var(--radius-sm);
  background: var(--crit-soft); color: var(--ink-2); font-size: var(--fs-meta);
}
.d-warn svg { color: var(--crit); flex: 0 0 auto; }

.d-two { display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(0, 1fr); gap: 12px; }
.d-two .card { display: flex; flex-direction: column; }

.d-score { display: flex; align-items: baseline; gap: 8px; }
.d-score b { font-size: var(--fs-number); font-weight: 700; line-height: 1; letter-spacing: -0.03em; }
.d-score b.tone-crit { color: var(--crit); }
.d-score b.tone-high { color: var(--high); }
.d-score b.tone-mid { color: var(--mid); }
.d-score b.tone-low { color: var(--low); }
.d-score span { color: var(--ink-3); font-size: var(--fs-micro); }
.d-factors { list-style: none; margin: 14px 0 0; padding: 0; display: grid; gap: 8px; }
.d-factors li { display: flex; align-items: center; justify-content: space-between; gap: 8px; color: var(--ink-2); font-size: var(--fs-meta); }
.d-factors b { color: var(--ink); }
.d-note { margin-top: 12px; color: var(--ink-3); font-size: var(--fs-micro); line-height: 1.6; }

.d-chain-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px 16px; }
.d-chain-item { display: grid; gap: 2px; min-width: 0; }
.d-chain-item span { color: var(--ink-3); font-size: var(--fs-micro); }
.d-chain-item b { color: var(--ink); font-size: var(--fs-body); font-weight: 600; overflow-wrap: anywhere; }

.d-selfcheck {
  display: flex; align-items: flex-start; gap: 8px; margin: 0 16px 16px;
  padding: 12px 12px; border-radius: var(--radius-sm); font-size: var(--fs-meta);
}
.d-selfcheck.ok { background: var(--low-soft); color: var(--ink-2); }
.d-selfcheck.bad { background: var(--crit-soft); color: var(--ink-2); }
.d-selfcheck.ok svg { color: var(--low); }
.d-selfcheck.bad svg { color: var(--crit); }
.d-selfcheck b { color: var(--ink); }
.d-selfcheck p { margin: 3px 0 0; }
.d-selfcheck ul { margin: 4px 0 0; padding-left: 16px; }

.d-json {
  margin: 0; max-height: 52vh; overflow: auto; padding: 12px;
  border-radius: var(--radius-sm); background: var(--surface-2); border: 1px solid var(--line);
  color: var(--ink-2); font-size: var(--fs-meta); line-height: 1.55;
}

.d-rise { animation: d-rise 0.34s cubic-bezier(0.22, 1, 0.36, 1) both; animation-delay: var(--d, 0ms); }
@keyframes d-rise {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: none; }
}

@media (max-width: 1100px) {
  .d-two { grid-template-columns: minmax(0, 1fr); }
  .d-fields .d-field-grid, .d-chain-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .d-readout, .d-score b { font-size: 26px; }
}

@media (max-width: 760px) {
  .d-hero { flex-direction: column; align-items: flex-start; }
  .d-readouts { gap: 16px; }
  .d-readout, .d-score b { font-size: 20px; }
  .d-hero-name { font-size: 20px; }
  .d-fields .d-field-grid, .d-chain-grid { grid-template-columns: minmax(0, 1fr); }
  .d-banner { max-width: 180px; }
  .btn { min-height: 36px; }
  tbody td { padding-top: 8px; padding-bottom: 8px; }
  tbody tr { height: 36px; }
}

@media (prefers-reduced-motion: reduce) {
  .d-rise { animation: none; }
}

@media print {
  .d-rise { animation: none; }
  .card { break-inside: avoid; }
}
</style>
