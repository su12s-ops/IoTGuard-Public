<template>
  <div class="kpi" :class="`tone-${tone}`">
    <div class="kpi-icon"><Icon :name="icon" :size="24" /></div>
    <div class="kpi-copy">
      <div class="kpi-label">{{ label }}</div>
      <div class="kpi-value-row">
        <span class="kpi-value">{{ displayValue }}</span>
        <span v-if="unit" class="kpi-unit">{{ unit }}</span>
        <span v-if="delta" class="kpi-delta" :class="deltaTone">
          <Icon :name="deltaTone === 'down' ? 'arrow-down' : 'arrow-up'" :size="12" />{{ delta }}
        </span>
      </div>
      <div v-if="sub" class="kpi-sub" :title="sub">{{ sub }}</div>
    </div>
  </div>
</template>

<script setup>
import { computed } from "vue";
import Icon from "./Icon.vue";

const props = defineProps({
  label: { type: String, required: true },
  value: { type: [Number, String], default: "—" },
  unit: { type: String, default: "" },
  icon: { type: String, default: "shield" },
  tone: { type: String, default: "blue" },
  delta: { type: String, default: "" },
  deltaTone: { type: String, default: "up" },
  sub: { type: String, default: "" }
});

const displayValue = computed(() => {
  const raw = props.value;
  if (typeof raw === "number" && Number.isFinite(raw)) return raw.toLocaleString("zh-CN");
  return raw === undefined || raw === null || raw === "" ? "—" : raw;
});
</script>
