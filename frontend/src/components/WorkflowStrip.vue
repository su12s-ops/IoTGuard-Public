<template>
  <div class="workflow-strip" aria-label="安全工作流">
    <template v-for="(step, index) in steps" :key="step.label">
      <div class="workflow-step" :style="{ '--step-color': step.color }">
        <span class="no">{{ index + 1 }}</span>
        <span>{{ step.label }}</span>
      </div>
      <i v-if="index < steps.length - 1" class="workflow-arrow" aria-hidden="true" />
    </template>
    <router-link class="link" :to="lastTo" style="margin-left: auto; padding-left: 16px">进入工作台 <Icon name="chev-right" :size="13" /></router-link>
  </div>
</template>

<script setup>
import Icon from "./Icon.vue";

const steps = [
  { label: "安全监测", color: "#f4622a" },
  { label: "资产发现", color: "#4f7df3" },
  { label: "漏洞风险", color: "#2f6fed" },
  { label: "智能研判", color: "#12b8a6" },
  { label: "安全执行", color: "#7c3aed" },
  { label: "效果验证", color: "#0ea5e9" }
];

const lastTo = "/runtime";
</script>
