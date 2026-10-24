"""Read historical reports without importing a retired LLM pipeline."""
from urllib.parse import urlparse

from app import config, models
from app.services.unified.schemas import PIPELINE_VERSION


def _endpoint_host(url: str) -> str:
    """Expose the configured endpoint host only, never credentials/query."""
    try:
        parsed = urlparse(url or "")
        return parsed.hostname or ""
    except ValueError:
        return ""


def latest_analysis(db):
    from app.routers.analysis import _serialize_run
    row = db.query(models.AnalysisReport).order_by(models.AnalysisReport.id.desc()).first()
    if row is None:
        return None
    return {**_serialize_run(row), "id": row.id, "review_run_id": row.review_run_id,
            "model": row.model, "is_legacy": not bool(row.pipeline_version)}


def review_status():
    from app.services.unified.agents_def import specs_summary
    return {"configured": bool(config.DEEPSEEK_API_KEY), "model": config.DEEPSEEK_MODEL,
        "mode": config.UNIFIED_PIPELINE_MODE, "pipeline_version": PIPELINE_VERSION,
        # Protocol and endpoint host are operational facts; the key and any
        # authorization header are never returned.
        "api_protocol": getattr(config, "DEEPSEEK_API_PROTOCOL", ""),
        "endpoint_host": _endpoint_host(getattr(config, "DEEPSEEK_BASE_URL", "")),
        "formal_writer": "unified" if config.UNIFIED_PIPELINE_MODE == "on" else "disabled",
        "agents": [{"id": s["name"], **s} for s in specs_summary()],
        "batch_size": 0, "batch_cap": 20,
        "batch_semantics": "0 = all eligible risks in scope, bounded to batch_cap",
        "pipeline": [{"step": i + 1, "name": name, "description": name} for i, name in enumerate(
            ["candidate", "evidence_preparing", "agent_reviewing", "conflict_review", "coordinator_review", "audit_policy"])]}
