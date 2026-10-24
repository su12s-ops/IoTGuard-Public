"""Built-console routes must work on Windows without swallowing API 404s."""
import importlib.util
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

spec = importlib.util.spec_from_file_location(
    "serve_local", Path(__file__).resolve().parents[2] / "scripts/serve_local.py")
serve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serve)


@pytest.fixture()
def console(tmp_path):
    (tmp_path / "index.html").write_text("<html>IoTGuard console</html>", encoding="utf-8")
    (tmp_path / "static").mkdir()
    (tmp_path / "static/app.js").write_text("console.log('ok')", encoding="utf-8")
    app = FastAPI()
    @app.get("/api/health")
    def health():
        return {"status": "ok"}
    app.mount("/", serve.ConsoleFiles(directory=tmp_path, html=True))
    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize("route", ["/", "/assets", "/risks", "/risks/1", "/risks/CVE-2026-63073", "/agents",
                                    "/repairs", "/runtime", "/reports", "/soc"])
def test_console_routes_support_direct_navigation(console, route):
    response = console.get(route)
    assert response.status_code == 200
    assert "IoTGuard console" in response.text


@pytest.mark.parametrize("route", ["/api/not-found", "/static/missing.js", "/unknown",
                                    "/risks/not-an-id", "/control-token.txt"])
def test_missing_api_or_private_files_never_return_app_shell(console, route):
    response = console.get(route)
    assert response.status_code == 404
    assert "IoTGuard console" not in response.text


def test_health_static_assets_and_head(console):
    assert console.get("/api/health").json() == {"status": "ok"}
    assert console.get("/static/app.js").status_code == 200
    assert console.head("/risks/1").status_code == 200
    assert console.post("/assets").status_code == 405
