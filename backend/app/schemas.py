from typing import Literal
from ipaddress import ip_address

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator


class ApiMessage(BaseModel):
    message: str
    count: int | None = None


class AgentAnalysisRequest(BaseModel):
    agent_id: str
    question: str


class TaskStatusUpdate(BaseModel):
    status: Literal["pending", "blocked", "in_progress", "fixed", "verified"]


class HumanReviewRequest(BaseModel):
    decision: Literal["confirm", "reject"]
    reason: str


class DemoTargetBase(BaseModel):
    id: int | None = None
    label: str
    target_type: Literal["ssh", "container"]
    enabled: bool = True
    host: str = ""
    ssh_port: int = 22
    username: str = ""
    password: str = ""
    asset_hostname: str = ""
    container_name: str = ""
    install_falco_if_missing: bool = False
    collect_asset: bool = True
    collect_runtime: bool = True
    notes: str = ""


class DemoTargetConfig(DemoTargetBase):
    id: int


class DemoTargetConfigUpdate(BaseModel):
    targets: list[DemoTargetBase]


class InventoryAsset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hostname: str = Field(min_length=1, max_length=128)
    distribution: str = Field(min_length=1, max_length=64)
    os_name: str = Field(default="", max_length=128)
    os_version: str = Field(default="", max_length=64)
    kernel_version: str = Field(default="", max_length=255)
    architecture: str = Field(default="", max_length=64)
    ip_address: str = Field(default="", max_length=64)
    mac_address: str = Field(default="", max_length=32)
    device_model: str = Field(default="", max_length=128)
    firmware_version: str = Field(default="", max_length=128)
    device_type: str = Field(default="linux_server", max_length=32)
    exposure_level: Literal["internal", "dmz", "public", "unknown"] = "internal"
    business_level: str = Field(default="normal", max_length=32)
    owner: str = Field(default="", max_length=128)
    description: str = Field(default="", max_length=2000)


class InventoryPackage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    package_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9+_.:\-]{0,127}$")
    package_version: str = Field(pattern=r"^[A-Za-z0-9+_.:~\-]{1,128}$")
    package_manager: Literal["apk", "opkg", "dpkg", "rpm"]
    architecture: str = Field(default="", pattern=r"^[A-Za-z0-9_.\-]{0,64}$")


class InventoryService(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service_name: str = Field(default="", max_length=128)
    port: int = Field(ge=1, le=65535, strict=True)
    protocol: Literal["tcp", "udp"]
    listen_address: str = Field(default="", max_length=128)
    process_name: str = Field(default="", max_length=128)
    is_public_exposed: StrictBool = False


class InventoryCollection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    collected_at: AwareDatetime
    source: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:\-]+$")
    collector_version: str = Field(default="", max_length=64)
    packages_complete: StrictBool
    package_count: int = Field(ge=0, le=50000, strict=True)
    parser_error_count: int = Field(ge=0, le=50000, strict=True)


class AssetInventoryDocument(BaseModel):
    """Project import contract, v1. External collectors need an explicit field adapter."""
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    asset: InventoryAsset
    collection: InventoryCollection
    packages: list[InventoryPackage] = Field(max_length=50000)
    services: list[InventoryService] = Field(default_factory=list, max_length=2000)

    @field_validator("schema_version", mode="before")
    @classmethod
    def strict_schema_version(cls, value):
        if type(value) is not int or value != 1:
            raise ValueError("仅支持整数 schema_version=1")
        return value

    @model_validator(mode="after")
    def consistent_inventory(self):
        if self.collection.parser_error_count or self.collection.package_count != len(self.packages):
            raise ValueError("软件包条数不一致或上游解析存在错误")
        if self.collection.packages_complete and not self.packages:
            raise ValueError("完整软件包清单不能为空")
        names = [p.package_name for p in self.packages]
        if len(set(names)) != len(names):
            raise ValueError("软件包名称重复")
        return self


class OpenWrtExportFirmware(BaseModel):
    model_config = ConfigDict(extra="forbid")
    distribution: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=64)
    revision: str = Field(default="", max_length=128)
    target: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=255)
    builddate: str = Field(default="", max_length=32)


class OpenWrtExportDevice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hostname: str = Field(min_length=1, max_length=100)
    model: str = Field(min_length=1, max_length=128)
    board_name: str = Field(min_length=1, max_length=128)
    system: str = Field(default="", max_length=255)
    kernel: str = Field(min_length=1, max_length=255)
    rootfs_type: str = Field(default="", max_length=64)
    firmware: OpenWrtExportFirmware
    mac_address: str = Field(default="", max_length=32)
    ip_address: str = Field(default="", max_length=64)


class OpenWrtExportPackage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9+_.\-]{0,127}$")
    version: str = Field(pattern=r"^[A-Za-z0-9+_.:~\-]{1,128}$")
    architecture: str = Field(pattern=r"^[A-Za-z0-9_.\-]{1,64}$")
    source: str = Field(default="", max_length=512)
    license: str = Field(default="", max_length=255)
    status: Literal["installed"]
    raw: str = Field(default="", max_length=4096)

    @model_validator(mode="after")
    def consistent_raw(self):
        if self.raw:
            fields = self.raw.split()
            manifest = fields == [self.name, self.version]
            detailed = (len(fields) >= 2 and fields[0] == f"{self.name}-{self.version}"
                        and fields[1] == self.architecture and self.raw.rstrip().endswith("[installed]"))
            if not manifest and not detailed:
                raise ValueError("软件包结构化字段与原始记录不一致")
        return self


class OpenWrtExportSoftware(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["apk list --installed", "apk list --installed --manifest"]
    raw_count: int = Field(ge=0, le=50000, strict=True)
    package_count: int = Field(ge=0, le=50000, strict=True)
    parse_error_count: int = Field(ge=0, le=50000, strict=True)
    packages: list[OpenWrtExportPackage] = Field(max_length=50000)


class OpenWrtExportManagement(BaseModel):
    """Declared connection metadata only; importing it never creates an SSH connection."""
    model_config = ConfigDict(extra="forbid")
    ip_address: str = Field(min_length=1, max_length=64)
    protocol: Literal["ssh"]
    port: int = Field(ge=1, le=65535, strict=True)
    authentication: Literal["ed25519_key"]
    key_reference: str = Field(min_length=1, max_length=512, pattern=r"^[^\r\n\x00]+$")

    @field_validator("ip_address")
    @classmethod
    def valid_address(cls, value):
        return str(ip_address(value))


class OpenWrtExportIntegrity(BaseModel):
    """Hashes of external source files, not hashes of this document's nested objects."""
    model_config = ConfigDict(extra="forbid")
    device_json_sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    packages_json_sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")


class OpenWrtExportDocument(BaseModel):
    """Ubuntu exporter layout established by the supplied 1.0 structure sample."""
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"]
    asset_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")
    asset_type: str = Field(min_length=1, max_length=64)
    collection_method: Literal["ssh", "offline"]
    generated_at: AwareDatetime
    device: OpenWrtExportDevice
    software_inventory: OpenWrtExportSoftware
    management: OpenWrtExportManagement | None = None
    integrity: OpenWrtExportIntegrity | None = None
    sample_only: StrictBool = False

    @model_validator(mode="after")
    def consistent_full_export(self):
        software = self.software_inventory
        if self.management and self.device.ip_address and str(ip_address(self.device.ip_address)) != self.management.ip_address:
            raise ValueError("管理地址与设备地址不一致")
        if self.sample_only:
            raise ValueError("结构样本不能作为真实完整资产导入")
        if not software.packages or software.parse_error_count or software.raw_count != software.package_count or software.package_count != len(software.packages):
            raise ValueError("清单为空、条数不一致或上游解析存在错误")
        if len({p.name for p in software.packages}) != len(software.packages):
            raise ValueError("软件包名称重复")
        return self


# ── 四智能体联合研判响应模型 ──

class AgentMetric(BaseModel):
    agent_name: str
    status: str  # completed | running | pending | failed
    objects_processed: int
    duration_ms: int | None = None
    error: str | None = None


class SkippedObject(BaseModel):
    object_id: str
    reason: str  # completed | has_task | status_not_candidate | data_missing
    detail: str = ""
    current_status: str = ""


class AnalysisRunSummary(BaseModel):
    run_id: str
    pipeline_version: str
    status: str
    termination_reason: str | None = None
    candidate_count: int = 0
    selected_object_count: int = 0
    processed_object_count: int = 0
    completed_object_count: int = 0
    human_review_object_count: int = 0
    current_stage: str | None = None
    agent_metrics: list[AgentMetric] = []
    selected_object_ids: list[str] = []
    skipped_objects: list[SkippedObject] = []
    verdict: dict | None = None
    error: str | None = None
    created_at: str = ""
    completed_at: str | None = None
