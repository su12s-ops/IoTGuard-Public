<template>
  <div v-if="props.nodes.length" class="layer-tree">
    <div class="layer-col" v-for="(col, ci) in columns" :key="col.type">
      <div class="col-head" :class="'ch-' + col.type">
        <span class="ch-dot"></span>{{ col.label }}<small>{{ col.total }}</small>
      </div>
      <div class="col-body">
        <div class="ln" :class="'ln-' + col.type" v-for="n in col.nodes" :key="n.id" :title="n.label + (n.version ? ' ' + n.version : '')">
          <span class="ln-name">{{ shortLabel(n.label) }}</span>
          <span class="ln-sub" v-if="col.type === 'asset' && n.ip_address">{{ n.ip_address }}</span>
          <span class="ln-sub" v-else-if="n.version">{{ n.version }}</span>
          <span class="ln-sub" v-else-if="col.type === 'cve'">受影响</span>
        </div>
        <div class="ln-more" v-if="col.overflow > 0">+{{ col.overflow }} 条</div>
        <div class="ln-empty" v-if="col.total === 0">—</div>
      </div>
      <span class="col-arrow" v-if="ci < columns.length - 1">→</span>
    </div>
  </div>
  <div v-else class="graph-empty" role="status">
    <strong>暂无可展示的依赖拓扑</strong>
    <span>请先完成资产采集与版本匹配，页面会自动展示资产、服务、软件包和 CVE 关系。</span>
  </div>
</template>

<script setup>
import { computed } from "vue";

const props = defineProps({
  nodes: { type: Array, default: () => [] },
  edges: { type: Array, default: () => [] }
});

const TYPE_LABEL = { asset: "资产", service: "服务", package: "软件包", cve: "CVE" };
const ORDER = ["asset", "service", "package", "cve"];
const PER_COL = 10;

const columns = computed(() =>
  ORDER.map((type) => {
    const all = (props.nodes || []).filter((n) => n.type === type);
    return {
      type,
      label: TYPE_LABEL[type],
      total: all.length,
      nodes: all.slice(0, PER_COL),
      overflow: Math.max(0, all.length - PER_COL)
    };
  })
);

const shortLabel = (l) => {
  const s = String(l || "");
  return s.length > 20 ? s.slice(0, 20) + "…" : s;
};
</script>

<style scoped>
.layer-tree {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 0;
  height: 100%;
  position: relative;
}
.graph-empty {
  min-height: 260px;
  display: grid;
  place-content: center;
  gap: 8px;
  padding: 24px;
  text-align: center;
  color: #94a3b8;
}
.graph-empty strong { color: #e2e8f0; }
.graph-empty span { max-width: 520px; line-height: 1.6; font-size: 13px; }
.layer-col {
  position: relative;
  display: flex;
  flex-direction: column;
  min-height: 0;
}
.layer-col + .layer-col {
  border-left: 1px dashed rgba(56, 189, 248, 0.12);
}

.col-head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  font-size: 13px;
  color: #cdd9ee;
  border-bottom: 1px solid rgba(56, 189, 248, 0.12);
}
.col-head small {
  margin-left: auto;
  font-family: Consolas, monospace;
  color: #8896ad;
  font-size: 12px;
}
.ch-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
}
.ch-asset .ch-dot { background: #607d9e; }
.ch-service .ch-dot { background: #4f8fe8; }
.ch-package .ch-dot { background: #8090a3; }
.ch-cve .ch-dot { background: #e05252; }

.col-body {
  flex: 1;
  overflow-y: auto;
  padding: 8px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.ln {
  padding: 6px 10px;
  border-radius: 2px;
  font-size: 12px;
  border: 1px solid;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.ln-name {
  font-family: Consolas, monospace;
  color: #e6edf7;
  word-break: break-all;
}
.ln-sub {
  font-size: 11px;
  color: #8896ad;
  font-family: Consolas, monospace;
}

.ln-asset {
  background: #14202b;
  border-color: #30465a;
}
.ln-asset .ln-name { color: #7dd3fc; }

.ln-service {
  background: #142033;
  border-color: #304b6a;
}
.ln-service .ln-name { color: #93c5fd; }

.ln-package {
  background: #181f2a;
  border-color: #384554;
}
.ln-package .ln-name { color: #c4b5fd; }

.ln-cve {
  background: #28191c;
  border-color: #67383c;
}
.ln-cve .ln-name { color: #ff8585; }
.ln-cve .ln-sub { color: #ff8585; }

.ln-more {
  text-align: center;
  color: #8896ad;
  font-size: 11.5px;
  padding: 4px;
}
.ln-empty {
  text-align: center;
  color: #475569;
  padding: 20px 0;
}

.col-arrow {
  position: absolute;
  right: -10px;
  top: 50%;
  transform: translateY(-50%);
  color: #607d9e;
  font-size: 18px;
  z-index: 2;
  text-shadow: none;
}
</style>
