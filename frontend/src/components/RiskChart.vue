<template>
  <div ref="chartEl" class="chart" role="img" :aria-label="title"></div>
</template>

<script setup>
import * as echarts from "echarts";
import { onBeforeUnmount, onMounted, ref, watch } from "vue";

const props = defineProps({
  title: { type: String, default: "风险图表" },
  type: { type: String, default: "pie" },
  data: { type: Array, default: () => [] }
});

const chartEl = ref(null);
let chart;

const render = () => {
  if (!chartEl.value) return;
  if (!chart) chart = echarts.init(chartEl.value);
  const option =
    props.type === "bar"
      ? {
          tooltip: {},
          grid: { left: 42, right: 18, top: 24, bottom: 36 },
          xAxis: { type: "category", data: props.data.map((item) => item.name), axisLabel: { interval: 0, rotate: 12 } },
          yAxis: { type: "value" },
          series: [{ type: "bar", data: props.data.map((item) => item.value), itemStyle: { color: "#1e40af" } }]
        }
      : {
          tooltip: { trigger: "item" },
          legend: { bottom: 0 },
          series: [
            {
              name: props.title,
              type: "pie",
              radius: ["42%", "68%"],
              center: ["50%", "42%"],
              data: props.data,
              color: ["#dc2626", "#d97706", "#2563eb", "#15803d"]
            }
          ]
        };
  chart.setOption(option);
};

onMounted(() => {
  render();
  window.addEventListener("resize", render);
});
watch(() => props.data, render, { deep: true });
onBeforeUnmount(() => {
  window.removeEventListener("resize", render);
  chart?.dispose();
});
</script>

<style scoped>
.chart {
  width: 100%;
  height: 300px;
}
</style>

