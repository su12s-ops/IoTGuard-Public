<template>
  <section class="page upgrade-page" v-loading="loading">
    <header class="page-header">
      <div>
        <span class="eyebrow">AGENT OPERATIONS</span>
        <h1>智能体分析与修复工作流</h1>
        <p>统一四智能体（资产与证据调查 → 漏洞分析 ∥ 运行时分析 → 研判与处置规划）；确定性聚合与审计门禁由程序完成，修复动作须经审批后由 Harness 执行。</p>
      </div>
      <div class="header-actions"><el-button @click="load">刷新</el-button></div>
    </header>
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" role="alert" />
    <DeviceControlToken />
    <el-tabs v-model="tab">
      <el-tab-pane label="四智能体分析" name="agents">
        <section class="operation-section">
          <div class="section-head">
            <div>
              <h2>发起编排分析</h2>
              <p class="operation-help">四个智能体各用专属工具读取真实数据（设备画像 / CVE·KEV·EPSS / eBPF 证据 / 白名单修复方案）；RISK 与 VERIFY 由程序确定性完成。</p>
            </div>
          </div>
          <el-form label-position="top" class="upgrade-form-grid" @submit.prevent="startAnalysis">
            <el-form-item label="目标（二选一）">
              <el-select v-model="analysisForm.target" filterable allow-create placeholder="选择设备或输入主机名" style="width: 100%">
                <el-option v-for="d in devices" :key="d.device_id" :value="d.device_id" :label="`${d.device_name}（${d.device_id}）`" />
              </el-select>
            </el-form-item>
            <el-form-item label="目标类型">
              <el-radio-group v-model="analysisForm.targetType">
                <el-radio value="device">智能设备</el-radio>
                <el-radio value="host">Linux 主机</el-radio>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="执行">
              <el-button type="primary" native-type="submit" :disabled="!canOperate || !analysisForm.target" :loading="starting">开始分析</el-button>
            </el-form-item>
          </el-form>
        </section>

        <section class="operation-section" v-if="agentRun">
          <div class="section-head">
            <div><h2>运行 {{ agentRun.run_id }}</h2><p>目标 {{ agentRun.target_ref }} · 状态 <el-tag size="small" :type="statusTag(agentRun.status)">{{ agentRun.status }}</el-tag></p></div>
            <el-button size="small" :loading="polling" @click="refreshAgentRun">轮询刷新</el-button>
          </div>
          <el-steps :active="stageActive" finish-status="success" align-center style="margin: 8px 0 14px">
            <el-step v-for="stage in stageOrder" :key="stage" :title="stage" :status="stepStatus(agentRun.stages[stage])" />
          </el-steps>
          <el-row :gutter="12">
            <el-col :span="12"><el-descriptions title="风险结论（程序聚合）" :column="1" border size="small">
              <el-descriptions-item label="优先级">{{ agentRun.risk.priority || '—' }}（{{ agentRun.risk.risk_score ?? '—' }} 分）</el-descriptions-item>
              <el-descriptions-item label="运行时等级">{{ agentRun.risk.runtime_level || '—' }}</el-descriptions-item>
              <el-descriptions-item label="依据">{{ agentRun.risk.rationale || '—' }}</el-descriptions-item>
            </el-descriptions></el-col>
            <el-col :span="12"><el-descriptions title="修复方案（白名单动作）" :column="1" border size="small">
              <el-descriptions-item v-for="(action, i) in agentRun.remediation.actions || []" :key="i" :label="action.action">
                {{ action.target }} — {{ action.rationale }}
              </el-descriptions-item>
              <el-descriptions-item v-if="!(agentRun.remediation.actions || []).length" label="动作">无</el-descriptions-item>
            </el-descriptions></el-col>
          </el-row>
          <h3 class="drawer-section-title">智能体执行明细（各自专属工具）</h3>
          <DataTable :rows="agentRows">
            <el-table-column prop="name" label="智能体" min-width="220" />
            <el-table-column label="状态" width="100"><template #default="{ row }">{{ row.status }}</template></el-table-column>
            <el-table-column label="工具调用" min-width="260"><template #default="{ row }">{{ (row.tool_calls || []).map(c => c.name).join('、') || '—' }}</template></el-table-column>
            <el-table-column prop="latency_ms" label="耗时(ms)" width="100" />
            <el-table-column label="错误" min-width="180"><template #default="{ row }">{{ row.error || '—' }}</template></el-table-column>
          </DataTable>
        </section>

        <section class="operation-section">
          <div class="section-head"><div><h2>历史运行</h2></div></div>
          <DataTable :rows="agentHistory">
            <el-table-column prop="run_id" label="运行" min-width="200" />
            <el-table-column prop="target_ref" label="目标" min-width="150" />
            <el-table-column label="状态" width="110"><template #default="{ row }"><el-tag size="small" :type="statusTag(row.status)">{{ row.status }}</el-tag></template></el-table-column>
            <el-table-column prop="created_at" label="创建时间" min-width="180"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
            <el-table-column label="操作" width="110"><template #default="{ row }"><el-button size="small" @click="viewAgentRun(row.run_id)">查看</el-button></template></el-table-column>
          </DataTable>
        </section>
      </el-tab-pane>

      <el-tab-pane label="统一编排（影子）" name="unified">
        <el-alert type="warning" :closable="false" show-icon style="margin-bottom: 12px"
          title="影子研判：统一四智能体（LangGraph 唯一编排器）在隔离入口运行，只写影子运行表，不改变正式风险结论、不触发设备写操作；正式入口仍由现有管线提供。" />
        <section class="operation-section">
          <div class="section-head">
            <div>
              <h2>影子运行列表</h2>
              <p class="operation-help">业务链：资产 → 候选 CVE → 原始证据 → 四智能体输出 → 确定性门禁 → 影子结论 → 待审批计划；每条运行可追溯到原始证据 ID。</p>
            </div>
            <el-select v-model="unifiedFilter.mode" size="small" style="width: 140px" @change="loadUnifiedRuns">
              <el-option value="" label="全部模式" />
              <el-option value="shadow" label="仅影子" />
              <el-option value="formal" label="仅正式" />
            </el-select>
          </div>
          <el-alert v-if="!unifiedLoading && unifiedRuns.length === 0" title="暂无统一编排运行" type="info" :closable="false" />
          <DataTable v-else :rows="unifiedRuns" v-loading="unifiedLoading" :height="280">
            <el-table-column prop="run_id" label="运行" min-width="210" />
            <el-table-column prop="task_type" label="任务" width="130" />
            <el-table-column prop="target_ref" label="目标" min-width="160" />
            <el-table-column label="模式" width="90">
              <template #default="{ row }">
                <el-tag size="small" :type="row.mode === 'shadow' ? 'warning' : 'success'">{{ row.mode === 'shadow' ? '影子' : '正式' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="100"><template #default="{ row }"><el-tag size="small" :type="statusTag(row.status)">{{ row.status }}</el-tag></template></el-table-column>
            <el-table-column prop="risk_id" label="风险" width="70" />
            <el-table-column prop="created_at" label="创建时间" min-width="170"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
            <el-table-column label="操作" width="100"><template #default="{ row }"><el-button size="small" @click="viewUnifiedRun(row.run_id)">查看</el-button></template></el-table-column>
          </DataTable>
        </section>

        <template v-if="unifiedRun">
          <section class="operation-section">
            <div class="section-head">
              <div>
                <h2>运行 {{ unifiedRun.run_id }}
                  <el-tag size="small" :type="unifiedRun.mode === 'shadow' ? 'warning' : 'success'" style="margin-left: 6px">{{ unifiedRun.mode === 'shadow' ? '影子研判' : '正式' }}</el-tag>
                </h2>
                <p class="operation-help">{{ unifiedRun.task_type }} · {{ unifiedRun.target_type }} {{ unifiedRun.target_ref }}
                  · 管线 {{ unifiedRun.pipeline_version }} · 状态 {{ unifiedRun.status }}{{ unifiedRun.error ? ' · ' + unifiedRun.error : '' }}</p>
              </div>
              <el-button size="small" :loading="unifiedLoading" @click="viewUnifiedRun(unifiedRun.run_id)">刷新</el-button>
            </div>
            <el-steps :active="unifiedStageActive" align-center style="margin: 8px 0 14px">
              <el-step v-for="stage in unifiedStageOrder" :key="stage" :title="stage"
                :status="stepStatus((unifiedRun.stage_status || {})[stage] ? { status: unifiedRun.stage_status[stage] === 'succeeded' ? 'succeeded' : unifiedRun.stage_status[stage] } : null)" />
            </el-steps>
            <el-row :gutter="12">
              <el-col :span="12">
                <el-descriptions title="确定性门禁（程序审计策略）" :column="1" border size="small">
                  <el-descriptions-item label="门禁状态">
                    <el-tag size="small" :type="(unifiedRun.final?.policy?.status) === 'auto_confirmed' ? 'success' : 'warning'">
                      {{ unifiedRun.final?.policy?.status || '—' }}
                    </el-tag>
                  </el-descriptions-item>
                  <el-descriptions-item label="理由">{{ (unifiedRun.final?.policy?.reasons || []).join('；') || '—' }}</el-descriptions-item>
                  <el-descriptions-item label="降级角色">{{ (unifiedRun.degraded_roles || []).join('、') || '无' }}</el-descriptions-item>
                  <el-descriptions-item label="LLM 用量">{{ JSON.stringify(unifiedRun.usage?.usage || unifiedRun.usage || {}) }}</el-descriptions-item>
                </el-descriptions>
              </el-col>
              <el-col :span="12">
                <el-descriptions title="影子结论（不写正式字段）" :column="1" border size="small">
                  <el-descriptions-item label="影响判定">{{ unifiedVerdict.impact_status || '—' }}</el-descriptions-item>
                  <el-descriptions-item label="建议处置">{{ unifiedVerdict.recommended_action || '—' }}（优先级 {{ unifiedVerdict.recommended_priority || '—' }}，置信度 {{ unifiedVerdict.confidence ?? '—' }}）</el-descriptions-item>
                  <el-descriptions-item label="证据有效性">{{ unifiedVerdict.runtime_evidence_validity || '—' }} / 紧迫度依据 {{ unifiedVerdict.urgency_basis || '—' }}</el-descriptions-item>
                  <el-descriptions-item label="引用证据">{{ (unifiedVerdict.supporting_evidence_ids || []).join('、') || '—' }}</el-descriptions-item>
                  <el-descriptions-item label="证据缺口">{{ (unifiedVerdict.missing_evidence || unifiedRun.final?.data_gaps || []).join('；') || '无' }}</el-descriptions-item>
                </el-descriptions>
              </el-col>
            </el-row>
            <div v-if="unifiedVerdict.reason" class="cell-sub" style="margin-top: 8px">研判依据：{{ unifiedVerdict.reason }}</div>
          </section>

          <section class="operation-section">
            <div class="section-head"><div><h2>四智能体执行明细（证据消费可追溯）</h2></div></div>
            <DataTable :rows="unifiedAgentRows">
              <el-table-column prop="name" label="智能体" min-width="180" />
              <el-table-column label="状态" width="90"><template #default="{ row }">{{ row.status || '—' }}</template></el-table-column>
              <el-table-column label="工具调用" min-width="280"><template #default="{ row }">{{ (row.tool_calls || []).join('、') || '—' }}</template></el-table-column>
              <el-table-column label="引用证据" min-width="240"><template #default="{ row }">{{ (row.evidence_ids || []).join('、') || '—' }}</template></el-table-column>
            </DataTable>
          </section>

          <section class="operation-section" v-if="unifiedPlanActions.length">
            <div class="section-head"><div><h2>待审批处置计划（requires_approval 由程序强制）</h2></div></div>
            <el-row :gutter="12">
              <el-col :span="8">
                <h3 class="drawer-section-title">建议动作（白名单）</h3>
                <el-descriptions :column="1" border size="small">
                  <el-descriptions-item v-for="(a, i) in unifiedPlanActions" :key="i" :label="a.action">
                    {{ a.target || a.package || '' }} {{ a.params ? JSON.stringify(a.params) : '' }}
                  </el-descriptions-item>
                </el-descriptions>
              </el-col>
              <el-col :span="8">
                <h3 class="drawer-section-title">验证条件</h3>
                <ul class="plan-list"><li v-for="(v, i) in (unifiedRun.plan?.verification_plan || [])" :key="i">{{ v.step || v.description || JSON.stringify(v) }}</li></ul>
              </el-col>
              <el-col :span="8">
                <h3 class="drawer-section-title">回滚要求</h3>
                <ul class="plan-list"><li v-for="(r, i) in (unifiedRun.plan?.rollback_plan || [])" :key="i">{{ r }}</li></ul>
              </el-col>
            </el-row>
          </section>

          <section class="operation-section" v-if="unifiedRun.mode === 'shadow' && unifiedRun.risk_id">
            <div class="section-head">
              <div><h2>与正式链路对照</h2>
                <p class="operation-help">影子结论只读对照同事件正式结论；正式字段仅由正式链路写入。</p>
              </div>
              <el-button size="small" :loading="unifiedLoading" @click="loadUnifiedComparison">加载对照</el-button>
            </div>
            <el-descriptions v-if="unifiedComparison" :column="1" border size="small">
              <el-descriptions-item label="统一（影子）">{{ JSON.stringify(unifiedComparison.unified?.policy || {}) }}</el-descriptions-item>
              <el-descriptions-item label="正式链路">{{ JSON.stringify(unifiedComparison.formal_snapshot || {}) }}</el-descriptions-item>
            </el-descriptions>
            <el-button v-else size="small" text type="primary" @click="$router.push({ path: '/risk', query: { tab: 'hits' } })">前往风险中心查看正式结论</el-button>
          </section>
        </template>
      </el-tab-pane>

      <el-tab-pane label="统一追踪 (Trace)" name="traces">
        <!-- A. 任务总览：真实记录聚合（无记录时如实空态） -->
        <section class="operation-section">
          <div class="section-head">
            <div>
              <h2>任务总览</h2>
              <p class="operation-help">数据来自 trace_run / trace_event 真实记录（第八阶段起生效；此前旧审计记录不回填、不在此伪造展示）。</p>
            </div>
            <el-button size="small" :loading="traceLoading" @click="loadTraceOverview">刷新统计</el-button>
          </div>
          <el-row :gutter="12" v-loading="traceLoading">
            <el-col :span="4"><el-statistic title="任务总数" :value="traceSummary.total_traces ?? 0" /></el-col>
            <el-col :span="4"><el-statistic title="成功" :value="traceSummary.by_status?.completed ?? 0" /></el-col>
            <el-col :span="4"><el-statistic title="失败" :value="traceSummary.by_status?.failed ?? 0" /></el-col>
            <el-col :span="4"><el-statistic title="运行中" :value="traceSummary.by_status?.running ?? 0" /></el-col>
            <el-col :span="4"><el-statistic title="策略拦截" :value="traceSummary.policy_blocked_traces ?? 0" /></el-col>
            <el-col :span="4">
              <el-statistic title="平均耗时(ms)" :value="typeof traceSummary.avg_duration_ms === 'number' ? traceSummary.avg_duration_ms : '—'" />
            </el-col>
          </el-row>
        </section>

        <!-- 任务列表：分页 + 过滤，选择一条 Trace 展示 B/C/D -->
        <section class="operation-section">
          <div class="section-head">
            <div><h2>追踪列表</h2></div>
            <el-select v-model="traceFilter.task_type" clearable placeholder="任务类型" size="small" style="width: 200px" @change="loadTraces">
              <el-option v-for="t in traceFilter.types" :key="t" :value="t" :label="t" />
            </el-select>
          </div>
          <el-alert v-if="!traceLoading && traces.length === 0" title="暂无追踪记录：发起一次四智能体分析、设备刷新/匹配或 Harness 任务后，将在此出现真实 Trace。" type="info" :closable="false" />
          <DataTable v-else :rows="traces" :height="260">
            <el-table-column prop="trace_id" label="Trace" min-width="200" />
            <el-table-column prop="task_type" label="任务类型" min-width="170" />
            <el-table-column prop="target_ref" label="目标" min-width="140" />
            <el-table-column label="状态" width="100"><template #default="{ row }"><el-tag size="small" :type="statusTag(row.status)">{{ row.status }}</el-tag></template></el-table-column>
            <el-table-column prop="event_count" label="事件数" width="80" />
            <el-table-column prop="created_at" label="开始时间" min-width="170"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
            <el-table-column label="操作" width="100"><template #default="{ row }"><el-button size="small" @click="viewTrace(row.trace_id)">详情</el-button></template></el-table-column>
          </DataTable>
          <el-pagination v-if="traceTotal > traceFilter.page_size" layout="prev, pager, next" :total="traceTotal"
            :page-size="traceFilter.page_size" :current-page="traceFilter.page" style="margin-top: 8px" @current-change="page => { traceFilter.page = page; loadTraces(); }" />
        </section>

        <template v-if="traceDetail">
          <!-- B. 智能体运行时间线 -->
          <section class="operation-section">
            <div class="section-head">
              <div>
                <h2>运行时间线 <el-tag size="small">{{ traceDetail.trace_id }}</el-tag></h2>
                <p class="operation-help">{{ traceDetail.task_type }} · 目标 {{ traceDetail.target_ref }} · 状态 {{ traceDetail.status }}{{ traceDetail.error ? ' · ' + traceDetail.error : '' }}</p>
              </div>
              <el-button size="small" :loading="traceLoading" @click="viewTrace(traceDetail.trace_id)">刷新</el-button>
            </div>
            <el-timeline v-if="traceDetail.events.length" style="margin-top: 6px">
              <el-timeline-item v-for="event in traceDetail.events" :key="event.id"
                :timestamp="`#${event.seq} ${formatTime(event.created_at)}`"
                :type="timelineType(event)" :hollow="event.status === 'running'">
                <strong>{{ event.actor || event.event_type }}</strong>
                <el-tag size="small" style="margin-left: 6px" :type="statusTag(event.status)">{{ event.event_type }}{{ event.status ? ' · ' + event.status : '' }}</el-tag>
                <el-tag v-if="event.is_llm_step" size="small" type="warning" style="margin-left: 6px">LLM</el-tag>
                <span v-if="event.duration_ms" class="cell-sub"> · {{ event.duration_ms }}ms</span>
                <div v-if="event.evidence_refs.length" class="cell-sub">证据引用：{{ event.evidence_refs.join('、') }}</div>
                <div v-if="agentSummary(event)" class="cell-sub">{{ agentSummary(event) }}</div>
                <el-collapse v-if="eventDetailLines(event).length" style="margin-top: 4px">
                  <el-collapse-item title="结构化摘要">
                    <pre class="trace-payload">{{ eventDetailLines(event).join("\n") }}</pre>
                  </el-collapse-item>
                </el-collapse>
              </el-timeline-item>
            </el-timeline>
            <el-empty v-else description="该追踪暂无事件" />
          </section>

          <el-row :gutter="12">
            <!-- C. Harness 安全监控 -->
            <el-col :span="12">
              <section class="operation-section">
                <div class="section-head"><div><h2>Harness 安全监控</h2></div></div>
                <el-descriptions :column="1" border size="small">
                  <el-descriptions-item label="关联状态">
                    <el-tag size="small" :type="traceHarness.association === 'linked' ? 'success' : 'info'">{{ harnessAssociationLabel(traceHarness.association) }}</el-tag>
                  </el-descriptions-item>
                  <el-descriptions-item v-if="traceHarness.harness" label="任务状态">{{ traceHarness.harness.status }}</el-descriptions-item>
                  <el-descriptions-item v-if="traceHarness.harness" label="审批">{{ traceHarness.harness.approval_hash === traceHarness.harness.plan_hash ? '已批准（哈希绑定）' : '未批准' }}</el-descriptions-item>
                  <el-descriptions-item v-if="traceHarness.harness" label="尝试次数">{{ traceHarness.harness.attempts }}</el-descriptions-item>
                </el-descriptions>
                <DataTable v-if="traceHarness.harness" :rows="traceHarness.harness.tool_calls" :height="240" style="margin-top: 8px">
                  <el-table-column prop="tool" label="工具" min-width="150" />
                  <el-table-column label="阶段" width="90"><template #default="{ row }">{{ row.phase }}</template></el-table-column>
                  <el-table-column label="写操作" width="80"><template #default="{ row }">{{ row.side_effect ? '是' : '否' }}</template></el-table-column>
                  <el-table-column label="状态" width="100"><template #default="{ row }"><el-tag size="small" :type="statusTag(row.status)">{{ row.status }}</el-tag></template></el-table-column>
                  <el-table-column prop="duration_ms" label="耗时(ms)" width="90" />
                </DataTable>
                <div v-if="harnessPolicyEvents.length" style="margin-top: 8px">
                  <h3 class="drawer-section-title">策略拦截事件</h3>
                  <el-alert v-for="(blocked, i) in harnessPolicyEvents" :key="i" type="warning" :closable="false"
                    :title="`${blocked.payload.check || 'policy'}：${(blocked.payload.reasons || []).join('；') || blocked.payload.error || ''}`" />
                </div>
              </section>
            </el-col>
            <!-- D. 证据关联视图 -->
            <el-col :span="12">
              <section class="operation-section">
                <div class="section-head">
                  <div><h2>证据关联</h2></div>
                  <el-button size="small" @click="jumpToTarget">跳转资产</el-button>
                </div>
                <DataTable :rows="traceEvidence.evidence || []" :height="200">
                  <el-table-column prop="evidence_id" label="SecurityEvidence" min-width="150" />
                  <el-table-column label="解析" width="90"><template #default="{ row }">{{ row.resolved ? '已解析' : 'unresolved' }}</template></el-table-column>
                  <el-table-column prop="evidence_type" label="类型" width="90" />
                  <el-table-column prop="severity" label="级别" width="90" />
                  <el-table-column prop="device_id" label="设备" min-width="120" />
                </DataTable>
                <DataTable :rows="traceEvidence.cves || []" :height="180" style="margin-top: 8px">
                  <el-table-column prop="cve_id" label="CVE" min-width="160" />
                  <el-table-column label="解析" width="90"><template #default="{ row }">{{ row.resolved ? '已解析' : 'unresolved' }}</template></el-table-column>
                  <el-table-column prop="cvss_score" label="CVSS" width="80" />
                  <el-table-column prop="cvss_severity" label="级别" width="100" />
                </DataTable>
                <div class="cell-sub" style="margin-top: 6px">{{ traceEvidence.note }}</div>
              </section>
            </el-col>
          </el-row>
        </template>
        <el-empty v-else-if="!traceLoading" description="从上方列表选择一条追踪查看时间线 / Harness / 证据关联" />
      </el-tab-pane>

      <el-tab-pane label="修复工作流" name="workflow">
        <section class="operation-section">
          <div class="section-head">
            <div>
              <h2>MQTT 匿名接入修复</h2>
              <p class="operation-help">真实探测 MQTT 是否允许匿名连接；修复动作（备份/改配置/重启）由设备侧白名单执行器完成，平台复核后判定 RESOLVED / ROLLBACK。</p>
            </div>
          </div>
          <el-form label-position="top" class="upgrade-form-grid" @submit.prevent="startWorkflow">
            <el-form-item label="MQTT 地址"><el-input v-model="workflowForm.host" aria-label="MQTT 地址" placeholder="目标 IP（须在后端允许网段内）" /></el-form-item>
            <el-form-item label="端口"><el-input-number v-model="workflowForm.port" :min="1" :max="65535" /></el-form-item>
            <el-form-item label="执行"><el-button type="primary" native-type="submit" :disabled="!canOperate" :loading="startingWorkflow">检测并创建</el-button></el-form-item>
          </el-form>
        </section>

        <section class="operation-section" v-if="workflow">
          <div class="section-head">
            <div><h2>工作流 {{ workflow.run_id }}</h2><p>目标 {{ workflow.target }} · 状态 <el-tag size="small" :type="statusTag(workflow.status)">{{ workflow.status }}</el-tag></p></div>
            <el-button size="small" @click="refreshWorkflow">刷新</el-button>
          </div>
          <el-timeline style="margin-top: 10px">
            <el-timeline-item timestamp="Before" type="warning">
              匿名连接：<strong>{{ workflow.before.anonymous_allowed ? '允许（漏洞存在，CONNACK rc=0）' : '已拒绝' }}</strong>
              <div class="cell-sub">证据 {{ workflow.evidence_id }}</div>
            </el-timeline-item>
            <el-timeline-item timestamp="Action" type="primary">
              <div v-for="(action, i) in workflow.actions" :key="i">{{ action.action }} → {{ action.result || action.target }}</div>
              <div v-if="!workflow.actions.length" class="cell-sub">未上报</div>
            </el-timeline-item>
            <el-timeline-item timestamp="After" type="info">
              <template v-if="workflow.verification.platform_recheck">
                匿名 rc={{ workflow.verification.platform_recheck.recheck?.anonymous?.return_code ?? '—' }}，
                认证 rc={{ workflow.verification.platform_recheck.recheck?.authenticated?.return_code ?? '—' }}
              </template>
              <span v-else class="cell-sub">等待上报</span>
            </el-timeline-item>
            <el-timeline-item timestamp="Verification" :type="workflow.status === 'RESOLVED' ? 'success' : workflow.status === 'ROLLBACK' ? 'warning' : 'info'">
              {{ workflow.status }}<div class="cell-sub" v-if="workflow.rollback.reason">回滚原因：{{ workflow.rollback.reason }}（恢复验证 {{ workflow.rollback.restored_ok }}）</div>
            </el-timeline-item>
          </el-timeline>
          <h3 class="drawer-section-title">实际执行命令</h3>
          <el-input type="textarea" :rows="Math.min(8, (workflow.commands || []).length || 1)" :model-value="(workflow.commands || []).join('\n')" readonly />
        </section>

        <section class="operation-section">
          <div class="section-head"><div><h2>历史工作流</h2></div></div>
          <DataTable :rows="workflowHistory">
            <el-table-column prop="run_id" label="工作流" min-width="200" />
            <el-table-column prop="target" label="目标" min-width="150" />
            <el-table-column label="状态" width="130"><template #default="{ row }"><el-tag size="small" :type="statusTag(row.status)">{{ row.status }}</el-tag></template></el-table-column>
            <el-table-column prop="created_at" label="创建时间" min-width="180"><template #default="{ row }">{{ formatTime(row.created_at) }}</template></el-table-column>
            <el-table-column label="操作" width="110"><template #default="{ row }"><el-button size="small" @click="viewWorkflow(row.run_id)">查看</el-button></template></el-table-column>
          </DataTable>
        </section>
      </el-tab-pane>
    </el-tabs>
  </section>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import { ElMessage } from "element-plus";
import DataTable from "../components/DataTable.vue";
import DeviceControlToken from "../components/DeviceControlToken.vue";
import {
  controlSession, errorMessage, fetchDevices,
  startAgentAnalysis, fetchAgentRuns, fetchAgentRun,
  startMqttWorkflow, fetchWorkflowRuns, fetchWorkflowRun,
  fetchTraces, fetchTraceSummary, fetchTraceDetail, fetchTraceHarness, fetchTraceEvidence,
  fetchUnifiedRuns, fetchUnifiedRun, fetchUnifiedComparison
} from "../api/deviceOperations";
import { useRouter, useRoute } from "vue-router";

const router = useRouter();
const route = useRoute();

const tab = ref("agents");
const loading = ref(false);
const error = ref("");
const devices = ref([]);
const agentHistory = ref([]);
const workflowHistory = ref([]);
const agentRun = ref(null);
const workflow = ref(null);
const starting = ref(false);
const startingWorkflow = ref(false);
const polling = ref(false);
let timer = null;
const analysisForm = reactive({ target: "", targetType: "device" });
const workflowForm = reactive({ host: "", port: 1883 });
const canOperate = computed(() => Boolean(controlSession.token));
const stageOrder = ["DEVICE", "VULNERABILITY", "RUNTIME", "RISK", "REMEDIATION", "VERIFY"];
const agentRows = computed(() => Object.entries(agentRun.value?.agents || {}).map(([name, log]) => ({ name, ...log })));
const stageActive = computed(() => {
  const stages = agentRun.value?.stages || {};
  const done = stageOrder.filter(s => ["succeeded", "failed"].includes(stages[s]?.status)).length;
  return agentRun.value?.status === "completed" || agentRun.value?.status === "failed" ? stageOrder.length : done;
});

const statusTag = value => ({ completed: "success", RESOLVED: "success", succeeded: "success", failed: "danger", FAILED: "danger", ROLLBACK: "warning", running: "primary", REMEDIATING: "primary", VERIFYING: "primary", DETECTED: "info" }[value] || "info");
const stepStatus = entry => ({ succeeded: "success", failed: "error", running: "process", pending: "wait" }[entry?.status] || "wait");
const formatTime = value => value ? new Date(value).toLocaleString("zh-CN") : "—";

async function load() {
  loading.value = true; error.value = "";
  try {
    [devices.value, agentHistory.value, workflowHistory.value] = await Promise.all([fetchDevices(), fetchAgentRuns(), fetchWorkflowRuns()]);
  } catch (e) { error.value = errorMessage(e); } finally { loading.value = false; }
}

async function startAnalysis() {
  starting.value = true; error.value = "";
  try {
    const payload = analysisForm.targetType === "device"
      ? { device_id: analysisForm.target } : { hostname: analysisForm.target };
    const result = await startAgentAnalysis(payload);
    ElMessage.success("编排已启动：" + result.run_id);
    await viewAgentRun(result.run_id);
    if (result.trace_id) { tab.value = "traces"; await viewTrace(result.trace_id); }
  } catch (e) { error.value = errorMessage(e); } finally { starting.value = false; }
}

async function viewAgentRun(runId) {
  agentRun.value = await fetchAgentRun(runId);
  if (agentRun.value.status === "running") startPolling();
}

function startPolling() {
  stopPolling();
  timer = window.setInterval(async () => {
    polling.value = true;
    try {
      agentRun.value = await fetchAgentRun(agentRun.value.run_id);
      if (agentRun.value.status !== "running") { stopPolling(); await load(); await loadTraceOverview(); }
    } catch { stopPolling(); }
    polling.value = false;
  }, 3000);
}
function stopPolling() { if (timer) { window.clearInterval(timer); timer = null; } }
async function refreshAgentRun() { if (agentRun.value) agentRun.value = await fetchAgentRun(agentRun.value.run_id); }

async function startWorkflow() {
  startingWorkflow.value = true; error.value = "";
  try {
    const result = await startMqttWorkflow({ host: workflowForm.host.trim(), port: workflowForm.port });
    if (result.status === "not_vulnerable") {
      ElMessage.success("检测完成：MQTT 不允许匿名连接，无需修复");
    } else {
      ElMessage.success(`检测到匿名接入（${result.run_id}），修复方案 ${result.plan.actions.length} 个动作已生成；请执行设备侧白名单执行器 run_mqtt_remediation_demo.sh`);
      workflow.value = await fetchWorkflowRun(result.run_id);
    }
    await load();
  } catch (e) { error.value = errorMessage(e); } finally { startingWorkflow.value = false; }
}
async function viewWorkflow(runId) { workflow.value = await fetchWorkflowRun(runId); }
async function refreshWorkflow() { if (workflow.value) workflow.value = await fetchWorkflowRun(workflow.value.run_id); }

// ── 统一四智能体影子编排（只读展示；业务链：资产→CVE→证据→四智能体→门禁→结论→计划）──
const unifiedLoading = ref(false);
const unifiedRuns = ref([]);
const unifiedRun = ref(null);
const unifiedComparison = ref(null);
const unifiedFilter = reactive({ mode: "shadow" });
const unifiedStageOrder = ["prepare", "prepare_evidence", "investigate_asset", "analyze_vulnerability",
  "analyze_runtime", "detect_conflicts", "directed_rereview", "decide", "execute_follow_ups", "finalize"];
const unifiedStageActive = computed(() => {
  const stages = unifiedRun.value?.stage_status || {};
  const done = unifiedStageOrder.filter(s => stages[s] === "succeeded").length;
  return unifiedRun.value?.status === "completed" ? unifiedStageOrder.length : done;
});
const unifiedVerdict = computed(() => {
  const decision = unifiedRun.value?.decision || {};
  return (decision.verdicts || [])[0] || {};
});
const unifiedPlanActions = computed(() => unifiedRun.value?.plan?.actions || []);
const unifiedAgentRows = computed(() =>
  Object.entries(unifiedRun.value?.agents || {}).map(([name, log]) => ({
    name,
    status: log.status,
    tool_calls: (log.tool_calls || []).map(c => c.name || c),
    evidence_ids: (log.output?.supporting_evidence_ids) || (log.output?.evidence_ids) || [],
  })));

async function loadUnifiedRuns() {
  unifiedLoading.value = true;
  try {
    unifiedRuns.value = await fetchUnifiedRuns(
      Object.fromEntries(Object.entries({ limit: 30, ...(unifiedFilter.mode ? { mode: unifiedFilter.mode } : {}) })));
  } catch (e) { error.value = errorMessage(e); } finally { unifiedLoading.value = false; }
}
async function viewUnifiedRun(runId) {
  unifiedLoading.value = true;
  unifiedComparison.value = null;
  try { unifiedRun.value = await fetchUnifiedRun(runId); }
  catch (e) { error.value = errorMessage(e); } finally { unifiedLoading.value = false; }
}
async function loadUnifiedComparison() {
  if (!unifiedRun.value) return;
  unifiedLoading.value = true;
  try { unifiedComparison.value = await fetchUnifiedComparison(unifiedRun.value.run_id); }
  catch (e) { error.value = errorMessage(e); } finally { unifiedLoading.value = false; }
}

// ── 统一追踪（第八阶段）：全部数据来自后端真实记录 ──
const traceLoading = ref(false);
const traceSummary = ref({});
const traces = ref([]);
const traceTotal = ref(0);
const traceDetail = ref(null);
const traceHarness = ref({});
const traceEvidence = ref({});
const traceFilter = reactive({ task_type: "", types: [], page: 1, page_size: 10 });

async function loadTraceOverview() {
  traceLoading.value = true;
  try {
    const [summary, listing] = await Promise.all([fetchTraceSummary(), fetchTraces({
      page: traceFilter.page, page_size: traceFilter.page_size, ...(traceFilter.task_type ? { task_type: traceFilter.task_type } : {})
    })]);
    traceSummary.value = summary;
    traces.value = listing.items;
    traceTotal.value = listing.total;
    traceFilter.types = listing.task_types || [];
  } catch (e) { error.value = errorMessage(e); } finally { traceLoading.value = false; }
}
async function loadTraces() { await loadTraceOverview(); }

async function viewTrace(traceId) {
  traceLoading.value = true;
  try {
    const [detail, harness, evidence] = await Promise.all([
      fetchTraceDetail(traceId), fetchTraceHarness(traceId), fetchTraceEvidence(traceId)]);
    traceDetail.value = detail;
    traceHarness.value = harness;
    traceEvidence.value = evidence;
  } catch (e) { error.value = errorMessage(e); } finally { traceLoading.value = false; }
}

const harnessPolicyEvents = computed(() =>
  (traceHarness.value.events || []).filter(e => e.event_type === "harness_policy_blocked"));
const timelineType = event => ({
  succeeded: "success", completed: "success", approved: "success",
  failed: "danger", blocked: "warning", unsupported: "warning", interrupted: "warning",
  running: "primary"
}[event.status] || (event.event_type === "task_finished" ? "success" : "info"));
const agentSummary = event => {
  if (!event.event_type.startsWith("agent_")) return "";
  const p = event.payload || {};
  const llm = p.llm ? `LLM ${p.llm.calls} 次（${p.llm.model}${p.llm.llm_tokens && p.llm.llm_tokens !== "unavailable" ? "" : "，用量 unavailable"}）` : "";
  return [p.attempts ? `尝试 ${p.attempts} 次` : "", llm, p.error ? `错误：${p.error}` : ""].filter(Boolean).join(" · ");
};
const eventDetailLines = event => {
  const p = event.payload || {};
  if (event.event_type.startsWith("agent_") && p.output_summary) {
    return Object.entries(p.output_summary).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`);
  }
  if (event.event_type === "capability_marks" && p.capabilities) {
    return Object.entries(p.capabilities).map(([k, v]) => `${k}: ${v}`);
  }
  return [];
};
const harnessAssociationLabel = value => ({
  linked: "已关联 Harness",
  not_requested: "未请求修复（只读分析，如实呈现，非修复成功）",
  not_applicable: "不适用（本任务类型无 Harness 环节）"
}[value] || value);
function jumpToTarget() {
  const detail = traceDetail.value;
  if (!detail) return;
  if (detail.target_type === "device") router.push("/devices");
  else if (detail.target_type === "linux_host" || detail.target_type === "asset") router.push("/assets");
  else if (detail.target_type === "cidr") router.push("/scan");
}

onMounted(async () => {
  load(); loadTraceOverview(); loadUnifiedRuns();
  // 深链：/agent-ops?tab=unified&run_id=xxx（风险详情页「统一四智能体影子研判」入口）
  if (route.query.tab === "unified") {
    tab.value = "unified";
    if (route.query.run_id) await viewUnifiedRun(String(route.query.run_id));
  }
});
onUnmounted(stopPolling);
</script>

<style scoped>
.drawer-section-title { margin: 18px 0 10px; font-size: 14px; font-weight: 600; }
.trace-payload { margin: 0; white-space: pre-wrap; word-break: break-all; font-size: 12px; max-height: 220px; overflow: auto; }
.cell-sub { color: var(--el-text-color-secondary); font-size: 12px; }
.plan-list { margin: 0; padding-left: 18px; font-size: 12px; color: var(--el-text-color-regular); }
.plan-list li { margin-bottom: 4px; }
</style>
