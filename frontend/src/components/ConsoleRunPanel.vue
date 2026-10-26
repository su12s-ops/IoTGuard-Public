<template>
  <section class="console-run" :class="{ 'has-error': !!flow?.error || !!consoleState.error }" aria-label="本轮自动流程">
    <div class="console-run-head">
      <div>
        <strong>{{ flow ? '本轮执行进度' : '准备开始新一轮' }}</strong>
        <span v-if="!flow" class="console-detail"> · {{ consoleState.selectedAssetLabel }}</span>
        <span v-else class="console-detail"> · {{ flow.round?.asset_hostname || (flow.asset_id ? '所选设备' : '全部接入设备') }}</span>
        <p role="status">{{ consoleState.error || flow?.error || flow?.message || '点击开始，自动获取官方情报、匹配版本、计算风险、运行四智能体并进入审核。' }}</p>
      </div>
      <router-link v-if="flow?.status === 'awaiting_review'" class="btn primary" to="/risks">进入人工审核</router-link>
      <button v-else class="btn primary" type="button" :disabled="consoleState.starting || consoleState.resetting || flow?.status === 'running' || flow?.status === 'completed'" @click="startWorkflow">
        <Icon :name="flow?.status === 'running' ? 'clock' : 'play'" :size="15" />
        {{ consoleState.starting ? '启动中…' : flow?.status === 'running' ? '正在执行' : flow?.status === 'completed' ? '本轮已完成' : '开始' }}
      </button>
    </div>
    <template v-if="flow">
      <div class="console-progress" role="progressbar" aria-label="本轮流程进度" :aria-valuenow="flow.progress_percent" aria-valuemin="0" aria-valuemax="100">
        <span :style="{ width: `${flow.progress_percent}%` }" />
      </div>
      <ol class="console-steps">
        <li v-for="(step, i) in flow.steps" :key="step.key" :class="step.status">
          <b>{{ step.status === 'completed' ? '✓' : i + 1 }}</b>
          <span>{{ step.label }}<small>{{ labels[step.status] || step.status }}</small></span>
        </li>
        <li class="console-percent">{{ flow.progress_percent }}%</li>
      </ol>
      <p v-if="flow.round?.counts" class="console-detail">
        匹配 {{ flow.round.counts.matches ?? 0 }} · 风险 {{ flow.round.counts.risks_calculated ?? 0 }}
        · 本批已处理 {{ flow.round.counts.processed ?? 0 }} / {{ flow.round.counts.selected ?? 0 }}
        <span v-if="flow.round.counts.remaining"> · 本批尚余 {{ flow.round.counts.remaining }} 项，{{ flow.status === 'running' ? '按后端批次上限依次处理' : '等待继续分析' }}</span>
      </p>
      <div v-if="flow.execution" class="console-detail" aria-live="polite">
        <p>本批实际运行 {{ flow.execution.active.length }} 项 · 排队 {{ flow.execution.queued_objects }} 项
          · 复用报告 {{ flow.execution.reused_reports }} 份</p>
        <p v-if="flow.execution.deferred_objects">未启动 {{ flow.execution.deferred_objects }} 项，等待后续分析。</p>
        <div v-for="item in flow.execution.active" :key="item.object_id">
          <p>{{ item.object_id }} · {{ item.roles.map(role => roleLabels[role] || role).join('、') || '正在汇总阶段结果' }}
            · 已耗时 {{ elapsed(item.elapsed_seconds) }}</p>
          <ul v-if="item.activity?.roles?.length">
            <li v-for="role in item.activity.roles" :key="role.role">
              {{ roleLabels[role.role] || role.role }}：{{ activityText(role) }}
              <span v-if="role.elapsed_seconds != null"> · 当前步骤 {{ elapsed(role.elapsed_seconds) }}</span>
            </li>
          </ul>
          <p v-if="item.activity?.totals?.observed">{{ item.activity.totals.partial ? '近期记录：' : '' }}模型请求 {{ item.activity.totals.model_requests }} 次，已返回 {{ item.activity.totals.model_responses }} 次
            · 累计排队 {{ item.activity.totals.queue_seconds }} 秒 · 模型等待 {{ item.activity.totals.model_seconds }} 秒（并行时间可重叠）</p>
          <details v-if="item.activity?.timeline?.length">
            <summary>最近执行记录（实际事件）</summary>
            <p v-for="(event, index) in item.activity.timeline" :key="index">
              {{ timeOf(event.at) }} · {{ roleLabels[event.role] || event.role }} · {{ eventLabels[event.event] || event.event }}
              <span v-if="event.tool"> · {{ toolLabels[event.tool] || event.tool }}</span>
            </p>
          </details>
        </div>
        <details v-if="flow.execution.recent_results?.length">
          <summary>本批最近完成结果与失败原因</summary>
          <div v-for="result in flow.execution.recent_results" :key="result.run_id">
            <b>{{ result.object_id }}</b>
            <p v-for="role in result.roles" :key="role.role">
              {{ roleLabels[role.role] || role.role }}：{{ activityText(role) }}
              <span v-if="role.timing"> · 本角色 {{ elapsed(role.timing.total_seconds) }}
                · 模型 {{ elapsed(role.timing.model_seconds || 0) }}
                · 排队 {{ elapsed(role.timing.queue_seconds || 0) }}
                · 取证 {{ elapsed(role.timing.tool_seconds || 0) }}
                <template v-if="role.timing.shared_wait_seconds"> · 等待共享报告 {{ elapsed(role.timing.shared_wait_seconds) }}</template>
              </span>
            </p>
            <p v-if="result.totals?.wall_seconds != null">整项实际耗时 {{ elapsed(result.totals.wall_seconds) }}；各角色并行时间可能重叠。</p>
          </div>
        </details>
        <p>候选发现、专业研判与人工审核分别完成；进度比例不代表剩余时间。</p>
      </div>
      <p v-if="flow.status === 'partial'" class="console-warning" role="status">
        本轮仅完成部分研判。已完成结果保留，未完成项仍需继续分析，不能据此判断安全。
      </p>
      <p v-if="flow.warnings?.length" class="console-warning">情报获取有 {{ flow.warnings.length }} 项限制：{{ flow.warnings[0] }}</p>
      <details v-if="Object.keys(flow.intelligence_snapshots || {}).length" class="console-detail">
        <summary>官方情报快照与时效</summary>
        <p v-for="(snapshot, ecosystem) in flow.intelligence_snapshots" :key="ecosystem">
          {{ ecosystem }} · {{ snapshot.advisory_count }} 条 ·
          {{ ({ recent: '本地内容在一天内更新', stale: '含超过一天的本地内容', unavailable: '无本地快照', unknown: '时间无法确认', invalid: '完整性校验失败' })[snapshot.status] || '状态未知' }}
          <br />本地内容更新时间：{{ snapshot.oldest_content_updated_at || '未知' }} 至 {{ snapshot.latest_content_updated_at || '未知' }}
          <br />远端最新性未验证 · 快照 SHA-256：{{ snapshot.sha256 || '无' }}
        </p>
      </details>
      <p v-if="flow.status === 'awaiting_review'" class="console-detail">人工审核需要操作员逐项裁定；提交后进度自动更新。</p>
    </template>
  </section>
</template>

<script setup>
import { computed } from "vue";
import Icon from "./Icon.vue";
import { consoleState, startWorkflow } from "../stores/consoleWorkflow";
const flow = computed(() => consoleState.workflow);
const labels = { pending: '待执行', running: '进行中', completed: '已完成', skipped: '已跳过', failed: '失败', partial: '部分完成', interrupted: '已中断' };
const roleLabels = { asset_investigator: '资产调查', vulnerability_analyst: '漏洞分析', runtime_analyst: '运行时分析', decision_planner: '决策汇总' };
const elapsed = seconds => `${Math.floor(Number(seconds || 0) / 60)} 分 ${Number(seconds || 0) % 60} 秒`;
const phaseLabels = { shared_report: '等待同设备共享报告（不会重复调用模型）', queue: '等待模型槽位（全局最多 2 个并发请求）', model: '等待模型生成并返回', tool: '正在查询原始证据', validating: '响应已返回，正在处理与校验', failed: '请求失败' };
const eventLabels = { task_waiting: '等待同设备共享报告', model_waiting: '进入模型请求队列', model_started: '模型请求已发出', model_finished: '模型响应已返回', model_failed: '模型请求失败', tool_started: '开始查询证据', tool_finished: '证据查询结束' };
const toolLabels = { query_runtime_data_quality: '查看覆盖与新鲜度', query_process_evidence: '查询进程证据', query_network_evidence: '查询网络证据', query_file_evidence: '查询文件证据', query_process_tree: '查看进程树' };
const failureLabels = { context_limit: '上下文超限', reasoning_output_exhausted: '推理耗尽输出额度，未产生报告', budget_limit: '预算耗尽', timeout: '执行超时', output_truncated: '模型报告被截断', evidence_validation: '证据或引用校验失败', report_format: '报告格式不合法', execution_error: '执行异常' };
const statusLabels = { succeeded: '报告已完成', reused: '已复用报告，未调用模型', finished: '执行结束，等待结果合并', running: '正在执行', failed: '执行失败', degraded: '角色未完成', timeout: '执行超时' };
const activityText = role => role.error
  ? `${failureLabels[role.failure_category] || '角色未完成'}：${role.error}`
  : (phaseLabels[role.phase] || statusLabels[role.status] || role.status || '等待执行');
const timeOf = value => value ? new Date(value).toLocaleTimeString('zh-CN', { hour12: false }) : '';
</script>

<style scoped>
.console-run { margin: 0 0 20px; padding: 18px 20px; background: white; border: 1px solid var(--line-soft); border-radius: 14px; }
.console-run-head { display: flex; justify-content: space-between; align-items: center; gap: 18px; }
.console-run-head strong { color: var(--ink); font-size: 15px; }
.console-run-head p, .console-detail, .console-warning { font-size: 12px; color: var(--muted); margin: 6px 0 0; line-height: 1.6; }
.console-warning { color: #b45309; }
.has-error .console-run-head p { color: #b42318; }
.has-error .console-progress span { background: #dc3232; }
.console-progress { height: 7px; border-radius: 8px; margin-top: 18px; overflow: hidden; background: #edf1f8; }
.console-progress span { display: block; height: 100%; background: #4169ed; transition: width .25s ease; }
.console-steps { display: flex; align-items: center; gap: 14px; padding: 0; margin: 15px 0 0; list-style: none; }
.console-steps li { display: flex; align-items: center; gap: 8px; flex: 1; color: var(--muted); font-size: 12px; }
.console-steps b { display: grid; place-items: center; width: 26px; height: 26px; border-radius: 50%; background: #eff3f9; }
.console-steps small { display: block; margin-top: 3px; }
.console-steps .completed { color: #128457; }
.console-steps .running { color: #3155dc; }
.console-steps .failed { color: #be3030; }
.console-steps .console-percent { flex: 0 0 auto; font-weight: 700; }
@media (max-width: 850px) { .console-steps { flex-wrap: wrap; } .console-steps li { flex: 1 1 28%; } .console-run-head { align-items: flex-start; } }
@media (prefers-reduced-motion: reduce) { .console-progress span { transition: none; } }
</style>
