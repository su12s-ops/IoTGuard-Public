from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class VulnerabilityInfo(Base):
    __tablename__ = "vulnerability_info"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(32), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, default="")
    cvss_score = Column(Float, default=0)
    cvss_severity = Column(String(32), default="Unknown")
    cwe_id = Column(String(64), default="")
    affected_product = Column(String(128), default="Linux")
    affected_package = Column(String(128), index=True, nullable=False)
    fixed_version = Column(String(128), default="")
    published_date = Column(String(32), default="")
    last_modified_date = Column(String(32), default="")
    source = Column(String(128), default="unknown")
    references = Column(Text, default="")
    remediation = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow)

    intel = relationship("ThreatIntelSource", back_populates="vulnerability", uselist=False)


class VulnerabilityIntelligenceSource(Base):
    """Global, source-isolated CVE intelligence cache.

    This table deliberately has no foreign key to ``vulnerability_info``.  A
    cached NVD/KEV/EPSS/Canonical fact belongs to the CVE, not to one scan or
    asset, and therefore survives the experiment lifecycle.
    """

    __tablename__ = "vulnerability_intelligence_source"
    __table_args__ = (
        UniqueConstraint("cve_id", "source", name="uq_vulnerability_intelligence_source"),
    )

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(32), index=True, nullable=False)
    source = Column(String(32), index=True, nullable=False)
    source_updated_at = Column(String(64), default="")
    fetched_at = Column(DateTime, default=utcnow, nullable=False)
    cache_expires_at = Column(DateTime, nullable=True)
    normalized_data = Column(Text, default="{}", nullable=False)
    fetch_status = Column(String(32), default="unavailable", nullable=False)
    error_message = Column(Text, default="")
    content_fingerprint = Column(String(64), default="")


class ThreatIntelSource(Base):
    __tablename__ = "threat_intel_source"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(32), ForeignKey("vulnerability_info.cve_id"), index=True, nullable=False)
    is_kev = Column(Boolean, default=False)
    kev_due_date = Column(String(32), default="")
    epss_score = Column(Float, default=0)
    epss_percentile = Column(Float, default=0)
    exploit_status = Column(String(64), default="unknown")
    poc_available = Column(Boolean, default=False)
    source_detail = Column(Text, default="")
    updated_at = Column(DateTime, default=utcnow)

    vulnerability = relationship("VulnerabilityInfo", back_populates="intel")


class LinuxAsset(Base):
    __tablename__ = "linux_asset"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(128), unique=True, index=True, nullable=False)
    ip_address = Column(String(64), default="")
    os_name = Column(String(128), default="")
    os_version = Column(String(64), default="")
    distribution = Column(String(64), default="")
    kernel_version = Column(String(255), default="")
    architecture = Column(String(64), default="")
    exposure_level = Column(String(32), default="internal")
    business_level = Column(String(32), default="normal")
    owner = Column(String(128), default="")
    description = Column(Text, default="")
    device_type = Column(String(32), default="linux_server")
    device_model = Column(String(128), default="")
    mac_address = Column(String(32), default="")
    firmware_version = Column(String(128), default="")
    identity_source = Column(String(64), default="uploaded_inventory")
    identity_confidence = Column(Float, default=0)
    capabilities_json = Column(Text, default="{}")
    inventory_complete = Column(Boolean, default=False)
    inventory_collected_at = Column(DateTime, nullable=True)
    inventory_sha256 = Column(String(64), default="")
    inventory_metadata_json = Column(Text, default="{}")
    inventory_external_id = Column(String(128), unique=True, nullable=True)
    last_seen_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    packages = relationship("AssetPackage", back_populates="asset", cascade="all, delete-orphan")
    services = relationship("AssetService", back_populates="asset", cascade="all, delete-orphan")


class DemoTarget(Base):
    __tablename__ = "demo_target"

    id = Column(Integer, primary_key=True, index=True)
    label = Column(String(128), default="")
    target_type = Column(String(32), default="ssh")
    enabled = Column(Boolean, default=True)
    host = Column(String(255), default="")
    ssh_port = Column(Integer, default=22)
    username = Column(String(128), default="")
    password = Column(String(255), default="")
    asset_hostname = Column(String(128), default="")
    container_name = Column(String(128), default="")
    install_falco_if_missing = Column(Boolean, default=False)
    collect_asset = Column(Boolean, default=True)
    collect_runtime = Column(Boolean, default=True)
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class AssetPackage(Base):
    __tablename__ = "asset_package"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("linux_asset.id"), index=True, nullable=False)
    package_name = Column(String(128), index=True, nullable=False)
    package_version = Column(String(128), default="")
    package_manager = Column(String(32), default="")
    architecture = Column(String(64), default="")
    installed_at = Column(String(64), default="")

    asset = relationship("LinuxAsset", back_populates="packages")


class AssetService(Base):
    __tablename__ = "asset_service"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("linux_asset.id"), index=True, nullable=False)
    service_name = Column(String(128), default="")
    port = Column(Integer, default=0)
    protocol = Column(String(16), default="tcp")
    listen_address = Column(String(128), default="")
    process_name = Column(String(128), default="")
    is_public_exposed = Column(Boolean, default=False)

    asset = relationship("LinuxAsset", back_populates="services")


class RuntimeEvent(Base):
    __tablename__ = "runtime_event"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("linux_asset.id"), index=True, nullable=True)
    hostname = Column(String(128), index=True, default="")
    source = Column(String(64), default="falco")
    event_type = Column(String(64), index=True, default="")
    category = Column(String(64), index=True, default="runtime")
    severity = Column(String(32), default="info")
    severity_score = Column(Integer, default=0)
    rule = Column(String(255), default="")
    process_name = Column(String(128), index=True, default="")
    parent_process = Column(String(128), default="")
    commandline = Column(Text, default="")
    file_path = Column(Text, default="")
    destination = Column(String(255), default="")
    port = Column(Integer, default=0)
    tactic = Column(String(128), default="")
    technique = Column(String(128), default="")
    risk_signal = Column(Text, default="")
    raw_json = Column(Text, default="")
    occurred_at = Column(String(64), default="")
    process_id = Column(Integer, default=0)
    parent_process_id = Column(Integer, default=0)
    process_exec_id = Column(String(255), default="")
    parent_exec_id = Column(String(255), default="")
    process_start_time = Column(String(64), default="")
    boot_id = Column(String(64), default="")
    sensor_id = Column(String(128), default="")
    executable = Column(Text, default="")
    container_id = Column(String(128), default="")
    # P2-1：幂等判重按此列逐事件查询，必须走索引（P0 部分唯一索引的谓词
    # 不被 SQLite 查询计划蕴含推理，实测判重仍全表扫描——见 database.py 注释）
    event_fingerprint = Column(String(64), default="", index=True)
    created_at = Column(DateTime, default=utcnow)


class VulnerabilityMatch(Base):
    __tablename__ = "vulnerability_match"
    __table_args__ = (
        UniqueConstraint("asset_id", "cve_id", "package_name", name="uq_vulnerability_match_event"),
    )

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("linux_asset.id"), index=True, nullable=False)
    cve_id = Column(String(32), index=True, nullable=False)
    package_name = Column(String(128), index=True, nullable=False)
    installed_version = Column(String(128), default="")
    fixed_version = Column(String(128), default="")
    affected = Column(Boolean, default=False)
    match_status = Column(String(32), default="unknown")
    reason_code = Column(String(64), default="unknown")
    match_reason = Column(Text, default="")
    confidence = Column(Float, default=0)
    evidence_fingerprint = Column(String(64), default="")
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class RiskAssessment(Base):
    __tablename__ = "risk_assessment"
    __table_args__ = (
        UniqueConstraint("match_id", name="uq_risk_assessment_match"),
    )

    id = Column(Integer, primary_key=True, index=True)
    match_id = Column(Integer, ForeignKey("vulnerability_match.id"), index=True, nullable=True)
    asset_id = Column(Integer, ForeignKey("linux_asset.id"), index=True, nullable=False)
    cve_id = Column(String(32), index=True, nullable=False)
    package_name = Column(String(128), index=True, default="")
    candidate_fingerprint = Column(String(64), default="")
    active = Column(Boolean, default=True)
    cvss_score = Column(Float, default=0)
    epss_score = Column(Float, default=0)
    kev_score = Column(Float, default=0)
    exposure_score = Column(Float, default=0)
    business_score = Column(Float, default=0)
    patch_score = Column(Float, default=0)
    static_score = Column(Float, default=0)
    runtime_score = Column(Float, default=0)
    environment_score = Column(Float, default=0)
    actionability_score = Column(Float, default=0)
    reachability_score = Column(Float, default=0)
    path_count = Column(Integer, default=0)
    exposed_service_count = Column(Integer, default=0)
    affected_status = Column(String(32), default="unknown")
    reachable_status = Column(String(32), default="none")
    runtime_status = Column(String(32), default="waiting")
    exploitability_status = Column(String(32), default="unlikely")
    decision = Column(String(32), default="monitor")
    decision_confidence = Column(Float, default=0)
    reachability_reason = Column(Text, default="")
    decision_reason = Column(Text, default="")
    final_score = Column(Float, default=0)
    risk_level = Column(String(32), default="Low")
    priority_rank = Column(Integer, default=0)
    reason = Column(Text, default="")
    applicability_source = Column(String(32), default="unknown")
    ubuntu_priority = Column(String(32), default="unknown")
    technical_severity = Column(String(32), default="unknown")
    likelihood_level = Column(String(32), default="unknown")
    known_exploited = Column(Boolean, default=False)
    risk_factors_json = Column(Text, default="{}")

    # ── 初步研判（确定性引擎输出）──────────────────────────────
    preliminary_score = Column(Float, default=0)
    preliminary_level = Column(String(32), default="Low")
    preliminary_decision = Column(String(32), default="monitor")
    preliminary_reason = Column(Text, default="")

    # ── 智能体协同复核 ─────────────────────────────────────────
    review_status = Column(String(32), default="pending")  # pending/running/completed/failed/skipped
    review_verdict = Column(String(32), default="")          # confirmed/upgraded/downgraded/insufficient_evidence
    review_confidence = Column(Float, default=0)
    review_adjustment = Column(Float, default=0)             # 风险分数调整（固定规则计算，非模型直写）
    review_evidence_ids = Column(Text, default="[]")          # JSON 数组
    review_conflicts = Column(Text, default="[]")             # JSON 数组
    review_missing_evidence = Column(Text, default="[]")      # JSON 数组
    review_reason = Column(Text, default="")
    review_completed_at = Column(DateTime, nullable=True)
    human_review_required = Column(Boolean, default=False)
    review_failed_agents = Column(Text, default="[]")       # JSON 数组：失败智能体 id
    evidence_packet_json = Column(Text, default="{}")
    agent_results_json = Column(Text, default="{}")
    conflict_result_json = Column(Text, default="{}")
    audit_policy_reasons = Column(Text, default="[]")
    recommended_priority = Column(String(32), default="")
    recommended_action = Column(String(64), default="")
    risk_direction = Column(String(32), default="maintain")
    reanalysis_count = Column(Integer, default=0)
    # Stage 9B F2/R1 对账：统一编排器设备级结论只读附加（不参与既有门禁）
    device_context_json = Column(Text, default="{}")
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    created_at = Column(DateTime, default=utcnow)


class RemediationTask(Base):
    __tablename__ = "remediation_task"

    id = Column(Integer, primary_key=True, index=True)
    risk_id = Column(Integer, ForeignKey("risk_assessment.id"), index=True, nullable=True)
    asset_id = Column(Integer, ForeignKey("linux_asset.id"), index=True, nullable=False)
    cve_id = Column(String(32), index=True, nullable=False)
    package_name = Column(String(128), index=True, nullable=False)
    current_version = Column(String(128), default="")
    target_version = Column(String(128), default="")
    remediation_command = Column(Text, default="")
    mitigation = Column(Text, default="")
    verification_command = Column(Text, default="")
    status = Column(String(32), default="pending")
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class AnalysisReport(Base):
    """四智能体联合研判报告：保存逐对象裁定、各智能体执行状态与完整对话记录。"""
    __tablename__ = "analysis_report"

    id = Column(Integer, primary_key=True, index=True)
    model = Column(String(128), default="")
    status = Column(String(32), default="running")   # running / completed / partial / failed / skipped / human_review / no_candidates
    answer = Column(Text, default="")                 # 协调智能体最终裁定说明
    transcript_json = Column(Text, default="")         # 完整对话记录 (JSON array)
    verdict_json = Column(Text, default="")            # 结构化裁定 (JSON) — 新格式为 object_verdicts 数组
    opinions_json = Column(Text, default="")           # 各智能体意见 (JSON)
    review_run_id = Column(String(32), default="")     # 本次复核运行 ID
    termination_reason = Column(String(64), default="")
    verdict_hit = Column(Boolean, default=False)
    verdict_parse_ok = Column(Boolean, default=False)
    turn_count = Column(Integer, default=0)
    error = Column(Text, default="")
    # ── 逐对象裁定统计 ──
    candidate_count = Column(Integer, default=0)       # 进入研判的候选对象数
    object_verdict_count = Column(Integer, default=0)  # 实际裁定的对象数
    # ── v2 扩展字段 ──
    pipeline_version = Column(String(64), default="")
    current_stage = Column(String(64), default="")
    selected_object_count = Column(Integer, default=0)
    processed_object_count = Column(Integer, default=0)
    completed_object_count = Column(Integer, default=0)
    human_review_object_count = Column(Integer, default=0)
    selected_object_ids_json = Column(Text, default="[]")
    skipped_objects_json = Column(Text, default="[]")
    progress_percent = Column(Integer, default=0)
    current_object_id = Column(String(64), default="")
    progress_message = Column(Text, default="")
    progress_sequence = Column(Integer, default=0)
    progress_updated_at = Column(DateTime, nullable=True)
    # ── 智能体执行状态 (JSON) ──
    agent_executions_json = Column(Text, default="{}") # 每个智能体的 status/attempts/duration_ms/output_valid/error
    created_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime, nullable=True)


class AgentAuditRecord(Base):
    """One structured, auditable LLM invocation bound to one risk event."""

    __tablename__ = "agent_audit_record"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(32), index=True, default="")
    risk_id = Column(Integer, ForeignKey("risk_assessment.id"), index=True, nullable=False)
    object_id = Column(String(64), index=True, nullable=False)
    agent_name = Column(String(64), index=True, nullable=False)
    model = Column(String(128), default="")
    evidence_ids_json = Column(Text, default="[]")
    structured_output_json = Column(Text, default="{}")
    raw_response = Column(Text, default="")
    parse_status = Column(String(32), default="pending")
    retry_count = Column(Integer, default=0)
    latency_ms = Column(Integer, default=0)
    error = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow)


class DeviceConnection(Base):
    """Connection metadata only; credentials remain in server environment variables."""
    __tablename__ = "device_connection"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("linux_asset.id"), unique=True, nullable=True)
    label = Column(String(128), default="")
    adapter = Column(String(32), default="openwrt_ssh")
    host = Column(String(64), nullable=False)
    port = Column(Integer, default=22)
    username = Column(String(64), default="root")
    credential_env = Column(String(128), nullable=False, default="")
    auth_type = Column(String(16), nullable=False, default="password")
    key_path_env = Column(String(128), nullable=False, default="")
    key_passphrase_env = Column(String(128), nullable=False, default="")
    host_key_sha256 = Column(String(128), nullable=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class DeviceObservation(Base):
    """Discovery evidence is deliberately separate from confirmed asset inventory.

    阶段五发现闭环：观察行携带处理状态（pending → identified /
    insufficient_evidence / failed），promoted_device_id 记录晋升到的
    IotDevice.device_id（业务键，非 IP），原始 evidence_json 永不删除。
    """
    __tablename__ = "device_observation"
    __table_args__ = (UniqueConstraint("scope", "identity_key", name="uq_device_observation"),)
    id = Column(Integer, primary_key=True)
    scope = Column(String(128), nullable=False)
    identity_key = Column(String(128), nullable=False)
    gateway_asset_id = Column(Integer, ForeignKey("linux_asset.id"), nullable=True)
    ip_address = Column(String(64), default="")
    mac_address = Column(String(32), default="")
    hostname = Column(String(128), default="")
    source = Column(String(32), default="tcp_connect")
    presence = Column(String(32), default="observed")
    evidence_json = Column(Text, default="{}")
    first_seen_at = Column(DateTime, default=utcnow)
    last_seen_at = Column(DateTime, default=utcnow)
    # ── 发现闭环处理状态（增量列，旧库经 DEVICE_OBSERVATION_COLUMN_MIGRATIONS 补齐） ──
    review_status = Column(String(32), default="pending", nullable=False, index=True)
    review_note = Column(Text, default="")
    review_attempts = Column(Integer, default=0)
    reviewed_at = Column(DateTime, nullable=True)
    promoted_device_id = Column(String(64), default="", index=True)


class OpenWrtAdvisory(Base):
    __tablename__ = "openwrt_advisory"
    __table_args__ = (UniqueConstraint("cve_id", "package_name", "release", name="uq_openwrt_advisory"),)
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(32), index=True, nullable=False)
    package_name = Column(String(128), nullable=False)
    release = Column(String(64), nullable=False)
    affected_versions_json = Column(Text, default="[]")
    fixed_versions_json = Column(Text, default="[]")
    source_url = Column(Text, nullable=False)
    notes = Column(Text, default="")
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class RuntimeSensor(Base):
    __tablename__ = "runtime_sensor"
    __table_args__ = (UniqueConstraint("asset_id", "sensor_id", name="uq_runtime_sensor"),)
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("linux_asset.id"), nullable=False)
    sensor_id = Column(String(128), nullable=False)
    source = Column(String(32), default="unknown")
    status = Column(String(32), default="unknown")
    capabilities_json = Column(Text, default="{}")
    dropped_events = Column(Integer, nullable=True)
    last_heartbeat_at = Column(DateTime, default=utcnow)
    detail = Column(Text, default="")


class HarnessRun(Base):
    __tablename__ = "harness_run"
    id = Column(String(32), primary_key=True)
    asset_id = Column(Integer, ForeignKey("linux_asset.id"), nullable=False)
    risk_id = Column(Integer, ForeignKey("risk_assessment.id"), nullable=True)
    connection_id = Column(Integer, ForeignKey("device_connection.id"), nullable=True)
    status = Column(String(32), default="pending")
    current_step = Column(String(64), default="")
    plan_json = Column(Text, default="{}")
    plan_hash = Column(String(64), default="")
    approval_hash = Column(String(64), default="")
    approved_by = Column(String(128), default="")
    approval_reason = Column(Text, default="")
    snapshot_json = Column(Text, default="{}")
    result_json = Column(Text, default="{}")
    error = Column(Text, default="")
    attempts = Column(Integer, default=0)
    # 第八阶段：统一追踪关联（空串=无追踪；由创建入口写入，不影响既有安全行为）
    trace_id = Column(String(48), default="", index=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    completed_at = Column(DateTime, nullable=True)


class HarnessToolCall(Base):
    __tablename__ = "harness_tool_call"
    id = Column(Integer, primary_key=True)
    run_id = Column(String(32), ForeignKey("harness_run.id"), index=True, nullable=False)
    tool = Column(String(64), nullable=False)
    status = Column(String(32), default="running")
    side_effect = Column(Boolean, default=False)
    arguments_json = Column(Text, default="{}")
    output_json = Column(Text, default="{}")
    error = Column(Text, default="")
    duration_ms = Column(Integer, default=0)
    created_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime, nullable=True)


# ── eBPF 运行时安全证据（阶段二：eBPF → Evidence → 数据库 → API → 智能体） ────


class CollectionEvidence(Base):
    __tablename__ = "collection_evidence"
    id = Column(Integer, primary_key=True)
    evidence_id = Column(String(64), unique=True, nullable=False)
    run_id = Column(String(64), index=True)
    asset_id = Column(Integer, ForeignKey("linux_asset.id"), index=True)
    content_sha256 = Column(String(64), nullable=False)
    raw_text = Column(Text, nullable=False)
    collected_at = Column(DateTime, default=utcnow)


class OfficialCveRecord(Base):
    """Append-only official response or failed fetch; never a runtime event."""
    __tablename__ = "official_cve_record"
    id = Column(Integer, primary_key=True)
    evidence_id = Column(String(64), unique=True, nullable=False)
    cve_id = Column(String(64), index=True, nullable=False)
    source_url = Column(Text, nullable=False)
    content_sha256 = Column(String(64), default="")
    raw_json = Column(Text, default="{}")
    evidence_status = Column(String(64), nullable=False)
    error = Column(Text, default="")
    fetched_at = Column(DateTime, default=utcnow)


class ApplicabilityCorrection(Base):
    __tablename__ = "applicability_correction"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("linux_asset.id"), index=True)
    risk_id = Column(Integer, ForeignKey("risk_assessment.id"), index=True)
    official_evidence_id = Column(String(64), index=True)
    before_json = Column(Text, default="{}")
    after_json = Column(Text, default="{}")
    historical_run_ids_json = Column(Text, default="[]")
    reason = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow)


class SecurityEvidence(Base):
    """eBPF / Falco / Tetragon 事件的统一安全证据层。

    由事件摄取管线自动生成：每条进入 RuntimeEvent 的运行时事件都会被
    归类为 process / network / file 三类之一并落库，供运行时 API 与
    四智能体研判直接消费，eBPF 不再只是独立日志。
    """

    __tablename__ = "security_evidence"
    __table_args__ = (
        UniqueConstraint("evidence_hash", name="uq_security_evidence_hash"),
        Index("ix_security_evidence_device_type", "device_id", "evidence_type"),
    )

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(String(64), unique=True, index=True, nullable=False)  # SE-<短哈希>
    device_id = Column(String(128), default="", index=True)     # IotDevice.device_id 或资产 hostname
    asset_id = Column(Integer, ForeignKey("linux_asset.id"), nullable=True, index=True)
    source = Column(String(64), default="")                      # falco / tetragon / ebpf_bpftrace / ...
    evidence_type = Column(String(32), default="", index=True)   # process / network / file
    timestamp = Column(String(64), default="", index=True)
    severity = Column(String(32), default="info", index=True)
    severity_score = Column(Integer, default=0)
    # ── 事件主体 ──
    process = Column(String(128), default="")
    pid = Column(Integer, default=0, index=True)
    ppid = Column(Integer, default=0)
    user = Column(String(64), default="")
    commandline = Column(Text, default="")
    parent_process = Column(String(128), default="")
    # ── P1-3 会话身份（与 RuntimeEvent 同源合成键；PID 复用可区分） ──
    process_exec_id = Column(String(255), default="", index=True)
    parent_exec_id = Column(String(255), default="")
    # ── 类型化明细 ──
    operation = Column(String(64), default="")    # exec/connect/read/write/...
    destination_ip = Column(String(64), default="")
    destination_port = Column(Integer, default=0)
    file_path = Column(Text, default="")
    description = Column(Text, default="")
    raw_data = Column(Text, default="{}")
    evidence_hash = Column(String(64), default="")
    created_at = Column(DateTime, default=utcnow)


class LsmPolicy(Base):
    """eBPF LSM 实验策略：默认只观察（observe），显式授权才允许 enforce。"""

    __tablename__ = "lsm_policy"
    __table_args__ = (UniqueConstraint("device_id", name="uq_lsm_policy_device"),)

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(128), nullable=False, index=True)  # 空串表示全局默认策略
    mode = Column(String(16), default="observe")                  # observe / enforce
    watch_paths_json = Column(Text, default="[]")
    restricted_processes_json = Column(Text, default="[]")
    enabled = Column(Boolean, default=True)
    updated_by = Column(String(128), default="")
    note = Column(Text, default="")
    # ── 采集端上报的内核能力（由 ebpf_lsm_monitor.py 探测后回传） ──
    kernel_bpf_lsm_supported = Column(Boolean, default=False)
    kernel_lsm_list = Column(Text, default="")
    capability_detail = Column(Text, default="")
    last_probe_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class HarnessAssetLock(Base):
    __tablename__ = "harness_asset_lock"
    asset_id = Column(Integer, ForeignKey("linux_asset.id"), primary_key=True)
    run_id = Column(String(32), ForeignKey("harness_run.id"), nullable=False)
    acquired_at = Column(DateTime, default=utcnow)


# ── 智能物联网设备清单（阶段一：设备发现 → 服务识别 → 组件识别） ──────────────
# 与 LinuxAsset（主机资产）并行存在：Linux 主机能力全部保留，智能设备走独立清单，
# 后续阶段再把设备接入漏洞匹配与四智能体研判。


class IotDevice(Base):
    """一台通过在线识别确认的智能物联网设备（如 SmartCam-X1 摄像头）。"""

    __tablename__ = "iot_device"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(64), unique=True, index=True, nullable=False)  # 稳定业务标识
    device_name = Column(String(128), default="", index=True)
    device_type = Column(String(64), default="unknown")      # ip_camera / gateway / unknown
    vendor = Column(String(128), default="")
    model = Column(String(128), default="")
    firmware_version = Column(String(128), default="")
    os = Column(String(128), default="")
    ip = Column(String(64), index=True, default="")
    status = Column(String(32), default="unknown")           # online / offline / unknown
    risk_score = Column(Float, default=0)                    # 当前为暴露基线分，CVE 评分在后续阶段接入
    risk_score_basis = Column(String(64), default="none")    # none / service_exposure_baseline
    security_status = Column(String(64), default="unassessed")
    identity_source = Column(String(64), default="network_identification")
    identity_confidence = Column(Float, default=0)
    metadata_json = Column(Text, default="{}")
    first_seen_at = Column(DateTime, default=utcnow)
    last_seen_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    services = relationship("IotDeviceService", back_populates="device", cascade="all, delete-orphan")
    components = relationship("IotDeviceComponent", back_populates="device", cascade="all, delete-orphan")


class IotDeviceService(Base):
    """设备上识别出的网络服务：Device → Service 关系的 Service 端。"""

    __tablename__ = "iot_device_service"
    __table_args__ = (UniqueConstraint("device_row_id", "port", name="uq_iot_device_service_port"),)

    id = Column(Integer, primary_key=True, index=True)
    device_row_id = Column(Integer, ForeignKey("iot_device.id"), index=True, nullable=False)
    port = Column(Integer, nullable=False)
    transport = Column(String(8), default="tcp")
    service_type = Column(String(32), default="unknown")     # ssh / http / mqtt / rtsp / unknown
    product = Column(String(128), default="")
    version = Column(String(64), default="")
    banner = Column(Text, default="")
    auth_state = Column(String(32), default="unknown")       # anonymous_accepted / auth_required / unknown
    status = Column(String(16), default="open")              # open / closed
    evidence_json = Column(Text, default="{}")
    first_seen_at = Column(DateTime, default=utcnow)
    last_seen_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    device = relationship("IotDevice", back_populates="services")
    components = relationship("IotDeviceComponent", back_populates="service", cascade="all, delete-orphan")


class IotDeviceComponent(Base):
    """从服务横幅/设备身份推导出的软件组件：Service → Component 与设备固件。"""

    __tablename__ = "iot_device_component"
    __table_args__ = (UniqueConstraint("device_row_id", "component_name", name="uq_iot_device_component_name"),)

    id = Column(Integer, primary_key=True, index=True)
    device_row_id = Column(Integer, ForeignKey("iot_device.id"), index=True, nullable=False)
    service_row_id = Column(Integer, ForeignKey("iot_device_service.id"), nullable=True)
    component_name = Column(String(128), nullable=False)
    component_type = Column(String(32), default="software")  # firmware / software
    version = Column(String(128), default="")
    cpe = Column(String(255), default="")
    source = Column(String(64), default="service_banner")    # device_identity / service_banner
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    device = relationship("IotDevice", back_populates="components")
    service = relationship("IotDeviceService", back_populates="components")


# ── MQTT 匿名接入修复工作流（阶段四：检测→分析→修复→重新检测→验证/回滚） ─────


class RemediationWorkflowRun(Base):
    """一条真实修复工作流的完整记录：Before / Action / After / Verification。

    状态机：DETECTED → REMEDIATING → VERIFYING → RESOLVED / ROLLBACK / FAILED。
    所有状态流转必须由真实动作（配置修改、服务重启、重新探测）驱动，
    禁止只改数据库状态。
    """

    __tablename__ = "remediation_workflow_run"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(48), unique=True, index=True, nullable=False)
    scenario = Column(String(64), default="mqtt_anonymous")
    target_host = Column(String(64), default="")
    target_port = Column(Integer, default=1883)
    status = Column(String(32), default="DETECTED", index=True)
    evidence_id = Column(String(64), default="")
    agent_plan_json = Column(Text, default="{}")     # Agent 分析产出的白名单修复方案
    before_json = Column(Text, default="{}")          # 修复前真实检测结果
    actions_json = Column(Text, default="[]")         # 实际执行的动作与命令
    after_json = Column(Text, default="{}")           # 修复后重新检测结果
    verification_json = Column(Text, default="{}")    # 验证结论（匿名失败/认证成功）
    rollback_json = Column(Text, default="{}")        # 回滚测试记录
    commands_json = Column(Text, default="[]")        # 设备侧实际执行的命令清单
    error = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    completed_at = Column(DateTime, nullable=True)


# ── 设备级 CVE 匹配（阶段六：厂商公告登记 → 精确版本匹配 → 设备风险） ────────


class IotDeviceAdvisory(Base):
    """智能设备厂商安全公告（操作员依据官方公告人工登记，与 OpenWrt 公告同语义）。

    登记内容不自动抓取或验证正文；匹配引擎只采信这里的精确版本记录。
    """

    __tablename__ = "iot_device_advisory"
    __table_args__ = (
        UniqueConstraint("cve_id", "vendor", "model", "component_name", name="uq_iot_device_advisory"),
    )

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(32), index=True, nullable=False)
    vendor = Column(String(128), default="")
    model = Column(String(128), nullable=False)
    component_name = Column(String(128), nullable=False)
    affected_versions_json = Column(Text, default="[]")
    fixed_versions_json = Column(Text, default="[]")
    source_url = Column(Text, default="")
    notes = Column(Text, default="")
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class DeviceVulnerabilityMatch(Base):
    """设备组件 × CVE 命中（设备侧对应主机的 VulnerabilityMatch）。"""

    __tablename__ = "device_vulnerability_match"
    __table_args__ = (
        UniqueConstraint("device_row_id", "cve_id", "component_name", name="uq_device_vulnerability_match"),
    )

    id = Column(Integer, primary_key=True, index=True)
    device_row_id = Column(Integer, ForeignKey("iot_device.id"), index=True, nullable=False)
    cve_id = Column(String(32), index=True, nullable=False)
    component_name = Column(String(128), index=True, nullable=False)
    installed_version = Column(String(128), default="")
    fixed_version = Column(String(128), default="")
    affected = Column(Boolean, default=False)
    match_status = Column(String(32), default="unknown")   # affected/fixed/not_applicable/insufficient_data
    reason_code = Column(String(64), default="unknown")
    match_reason = Column(Text, default="")
    confidence = Column(Float, default=0)
    applicability_source = Column(String(32), default="unknown")  # vendor_advisory / nvd_generic
    evidence_fingerprint = Column(String(64), default="")
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


# ── 四智能体编排记录（阶段三：程序负责流程/状态/超时/重试/校验） ───────────────


class UnifiedAnalysisRun(Base):
    """统一四智能体编排（Stage 9B）：唯一正式编排器的运行记录。

    mode=shadow 时本表是影子结果（不影响正式链路）；mode=formal 时经
    兼容适配层接入正式入口。历史实验数据保留原 pipeline_version 标识。
    """

    __tablename__ = "unified_analysis_run"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(48), unique=True, index=True, nullable=False)
    task_type = Column(String(32), default="risk_review")     # risk_review / device_surface / focused_review
    target_type = Column(String(32), default="linux_host")
    target_ref = Column(String(128), default="", index=True)
    mode = Column(String(16), default="shadow")               # shadow / formal
    status = Column(String(32), default="running")            # running/completed/failed
    pipeline_version = Column(String(48), default="unified-four-agent-v1")
    routing_json = Column(Text, default="{}")                 # 路由决策（分层/跳过角色/理由）
    state_json = Column(Text, default="{}")                   # 有状态工作流快照（节点边界）
    agents_json = Column(Text, default="{}")                  # 每智能体执行摘要（工具/重试/反馈）
    decision_json = Column(Text, default="{}")                # 决策规划师结构化输出
    plan_json = Column(Text, default="{}")                    # 候选修复计划（恒 requires_approval）
    usage_json = Column(Text, default="{}")                   # 真实 LLM 调用/Token 计量
    risk_id = Column(Integer, index=True, nullable=True)      # risk_review 的事件 ID
    error = Column(Text, default="")
    trace_id = Column(String(48), default="", index=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    completed_at = Column(DateTime, nullable=True)


class AgentOrchestrationRun(Base):
    """一次 DEVICE→VULNERABILITY→RUNTIME→RISK→REMEDIATION→VERIFY 编排的完整状态。"""

    __tablename__ = "agent_orchestration_run"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(48), unique=True, index=True, nullable=False)
    target_type = Column(String(32), default="device")        # device / linux_host
    target_ref = Column(String(128), default="", index=True)  # device_id / hostname
    status = Column(String(32), default="running")            # running/completed/failed
    stages_json = Column(Text, default="{}")                  # 每阶段状态与输出
    agents_json = Column(Text, default="{}")                  # 每智能体执行摘要（工具调用/重试/耗时）
    risk_json = Column(Text, default="{}")
    remediation_json = Column(Text, default="{}")
    verify_json = Column(Text, default="{}")
    error = Column(Text, default="")
    # 第八阶段：统一追踪关联（新记录写入；旧记录保持空串=无追踪，不回填不伪造）
    trace_id = Column(String(48), default="", index=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    completed_at = Column(DateTime, nullable=True)


# ── 统一任务追踪（第八阶段：四智能体 + Harness + 设备管线共用 Trace） ─────────


class TraceRun(Base):
    """一次独立安全任务的统一追踪根记录。

    trace_id 全局唯一；同一任务的智能体步骤、工具调用、Harness 事件、
    证据引用全部通过 trace_event 追加记录并保持发生顺序。
    旧审计表（AgentAuditRecord / AgentOrchestrationRun / HarnessRun）不迁移、
    不回填 trace_id——旧数据保持原样可读，新任务才产生 Trace。
    """

    __tablename__ = "trace_run"
    __table_args__ = (
        Index("ix_trace_run_created", "created_at"),
        Index("ix_trace_run_type_status", "task_type", "status"),
    )

    id = Column(Integer, primary_key=True, index=True)
    trace_id = Column(String(48), unique=True, index=True, nullable=False)
    task_type = Column(String(48), default="", index=True)
    # four_agent_analysis / device_refresh / device_cve_match / discovery_enrollment /
    # harness_investigate / harness_repair / harness_collect
    target_type = Column(String(32), default="")   # device / linux_host / cidr / asset
    target_ref = Column(String(128), default="", index=True)
    run_ref_type = Column(String(48), default="")  # agent_orchestration / harness / device_task
    run_ref_id = Column(String(64), default="")    # 关联既有运行记录主键（run_id / harness id）
    harness_run_id = Column(String(32), default="", index=True)  # Harness 关联（可空）
    status = Column(String(32), default="running")  # running/completed/failed/blocked
    summary_json = Column(Text, default="{}")
    error = Column(Text, default="")
    started_at = Column(DateTime, default=utcnow)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class TraceEvent(Base):
    """追踪事件（只追加）：保持发生顺序，记录证据引用与结构化摘要。

    seq 为 trace 内单调递增序号（分配时 SELECT MAX+1，SQLite 写串行化足够）；
    id 为全局自增，两者都可用于排序校验。payload 经服务端脱敏并限长。
    """

    __tablename__ = "trace_event"
    __table_args__ = (
        Index("ix_trace_event_trace_seq", "trace_id", "seq"),
        Index("ix_trace_event_type", "event_type"),
    )

    id = Column(Integer, primary_key=True, index=True)
    trace_id = Column(String(48), index=True, nullable=False)
    seq = Column(Integer, default=0)
    event_type = Column(String(48), default="")
    # task_started/task_finished/agent_started/agent_finished/agent_failed/
    # stage_started/stage_finished/handoff/llm_result/tool_called/tool_failed/
    # harness_plan/harness_approved/harness_policy_blocked/harness_tool_started/
    # harness_tool_finished/harness_tool_failed/harness_finished/harness_rollback/
    # capability_marks/cve_match/policy_blocked/...
    actor = Column(String(64), default="")         # 智能体名 / orchestrator / harness / pipeline
    status = Column(String(32), default="")        # succeeded/failed/timeout/blocked/unsupported...
    is_llm_step = Column(Boolean, default=False)   # 大模型步骤如实标注（程序步骤不得伪装）
    payload_json = Column(Text, default="{}")
    evidence_refs_json = Column(Text, default="[]")  # evidence_id / CVE 等证据引用
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, default=0)
    created_at = Column(DateTime, default=utcnow)


# ── 互联网授权目标主动扫描（阶段六：双重授权 → 端口扫描 → 指纹 → CVE 匹配） ──


class ScanTarget(Base):
    """一个已登记的互联网授权扫描目标（自有 VPS / 云主机 / 书面授权主机）。

    双重授权的第二层：第一层是后端 LINUXGUARD_DISCOVERY_CIDRS 网段白名单
    （allowed_host 在登记与每次扫描时都重新校验），第二层是本表里操作员
    显式登记的授权依据。仅接受 IP 字面量，不接受域名。
    """

    __tablename__ = "scan_target"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), default="", index=True)
    ip_address = Column(String(64), unique=True, index=True, nullable=False)
    authorization_basis = Column(Text, nullable=False)  # 授权依据（自有/书面授权说明，必填）
    ports_profile_json = Column(Text, default="[]")     # 扫描端口列表（≤128），空则用默认画像
    enabled = Column(Boolean, default=True)
    notes = Column(Text, default="")
    last_run_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class ScanRun(Base):
    """一次主动扫描的完整审计记录：扫描参数、开放端口、识别结论与匹配统计。

    只记录真实探测到的事实；无响应不能证明服务不存在，banner 可伪造，
    版本结论以低置信度呈现——这些边界由 scan_service 写入 findings。
    """

    __tablename__ = "scan_run"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(48), unique=True, index=True, nullable=False)
    target_id = Column(Integer, ForeignKey("scan_target.id"), index=True, nullable=False)
    target_ip = Column(String(64), default="")
    status = Column(String(32), default="running", index=True)  # running/completed/failed
    ports_scanned = Column(Text, default="[]")          # 实际扫描的端口列表
    open_ports_json = Column(Text, default="[]")        # TCP 连接成功的端口
    identified_services_json = Column(Text, default="[]")  # 协议识别成功的服务摘要
    unmatched_ports_json = Column(Text, default="[]")   # 开放但未识别协议的端口（仅存 banner）
    ports_scanned_count = Column(Integer, default=0)
    open_ports_count = Column(Integer, default=0)
    identified_count = Column(Integer, default=0)
    vulnerability_hits = Column(Integer, default=0)     # 本次扫描后设备受影响的 CVE 数
    device_id = Column(String(64), default="", index=True)  # 关联的 IotDevice.device_id
    findings = Column(Text, default="{}")               # 汇总结论与边界说明
    error = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    completed_at = Column(DateTime, nullable=True)
