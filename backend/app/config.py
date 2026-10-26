import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.getenv("LINUXGUARD_DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# 加载 .env 文件（优先级：.env.local > .env）
_env_local = BASE_DIR / ".env.local"
_env_default = BASE_DIR / ".env"
if os.getenv("PYTHON_DOTENV_DISABLED") == "1" or os.getenv("LINUXGUARD_DEPLOYMENT_MODE") == "collection_only":
    pass
elif _env_local.exists():
    load_dotenv(_env_local)
elif _env_default.exists():
    load_dotenv(_env_default)

DATABASE_URL = os.getenv("LINUXGUARD_DATABASE_URL", f"sqlite:///{DATA_DIR / 'linuxguard.db'}")
if os.getenv("LINUXGUARD_DEPLOYMENT_MODE") == "collection_only":
    from app.integration_runtime import validate_environment
    validate_environment(os.environ)
API_TITLE = os.getenv("LINUXGUARD_API_TITLE", "LinuxGuard API")
API_VERSION = os.getenv("LINUXGUARD_API_VERSION", "0.2.0")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash")
# LLM 端点协议：openai（OpenAI 兼容 /chat/completions）| anthropic（Messages 协议，
# 如 BigModel GLM 套餐计费端点 /api/anthropic）。变量名沿用 DEEPSEEK_* 保持零迁移成本。
DEEPSEEK_API_PROTOCOL = os.getenv("DEEPSEEK_API_PROTOCOL", "openai")
# 兼容旧配置；task_graph 按模型支持设置控制参数，GLM-5.3 使用 enabled/low。
DEEPSEEK_THINKING = os.getenv("DEEPSEEK_THINKING", "")

# M5：唯一四智能体；on 为正式入口，off/shadow 禁止正式任务，无旧 LLM fallback。
UNIFIED_PIPELINE_MODE = os.getenv("LINUXGUARD_UNIFIED_PIPELINE", "off").strip().lower()
if UNIFIED_PIPELINE_MODE not in {"off", "shadow", "on"}:
    UNIFIED_PIPELINE_MODE = "off"

# Explicit rollout: task_graph writes through the same formal sink and requires
# human review until paired quality validation is completed. Existing deployments
# retain their chosen mode; no running worker changes mode mid-flight.
REVIEW_EXECUTION_MODE = os.getenv("LINUXGUARD_REVIEW_EXECUTION", "legacy").strip().lower()
if REVIEW_EXECUTION_MODE not in {"legacy", "task_graph"}:
    raise ValueError("LINUXGUARD_REVIEW_EXECUTION must be legacy or task_graph")
