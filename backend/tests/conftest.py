import ipaddress
import os
import sys
import tempfile
import socket
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


# The application lifespan uses the production SessionLocal. Tests override
# request dependencies, but that does not affect startup cleanup, so disable
# destructive startup cleanup before importing app.main.
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ["DEEPSEEK_API_KEY"] = ""
os.environ["NVD_API_KEY"] = ""
for _name in ("VM_HOST", "VM_HOSTS", "VM_PORT", "VM_PORTS", "VM_USER", "VM_PASS", "BIONIC_CONTAINER"):
    os.environ[_name] = ""
os.environ["LINUXGUARD_ARCHIVE_ON_STARTUP"] = "0"
_isolated_runtime = tempfile.TemporaryDirectory(prefix="linuxguard-tests-", ignore_cleanup_errors=True)
os.environ["LINUXGUARD_DATABASE_URL"] = "sqlite:///" + str(Path(_isolated_runtime.name) / "startup.db")
os.environ["LINUXGUARD_EVENT_FILE"] = str(Path(_isolated_runtime.name) / "events.jsonl")
os.environ["REPORT_ARCHIVE_DIR"] = str(Path(_isolated_runtime.name) / "archives")
os.environ["LINUXGUARD_REPAIR_MANIFEST"] = ""
os.environ["LINUXGUARD_CONTROL_TOKEN"] = ""
os.environ["LINUXGUARD_DEPLOYMENT_MODE"] = "standard"
os.environ["LINUXGUARD_COLLECTOR_NODE_ID"] = "isolated-test"
os.environ["LINUXGUARD_DATA_DIR"] = str(Path(_isolated_runtime.name) / "data")


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import config as _test_config  # noqa: E402
_test_config.DATA_DIR = Path(_isolated_runtime.name) / "data"
_test_config.DATA_DIR.mkdir(exist_ok=True)

from app import models  # noqa: E402,F401
from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402


def pytest_sessionstart(session):
    """Regression runs may use only their temporary SQLite files and no external network.

    环回（127.0.0.0/8、::1、localhost）放行：回归中的环回端点只可能是
    进程内/本机测试桩（MQTT broker 桩、HTTP 桩、模拟器——钩子自己规定的
    "use a test double" 模式）。数字 IP 的 getaddrinfo 不经过 DNS，同样
    放行；主机名解析与一切非环回连接仍然阻断——"无真实网络"的保护
    语义保持不变。（此前钩子连 create_connection 对 127.0.0.1 的内部
    getaddrinfo 都拦截，导致 19 个按设计使用本地桩的测试全部失败。）
    """
    roots = (Path(_isolated_runtime.name).resolve(), session.config._tmp_path_factory.getbasetemp().resolve())

    def _is_loopback(address) -> bool:
        try:
            host = address[0] if isinstance(address, tuple) else address
            parsed = ipaddress.ip_address(str(host))
        except ValueError:
            return str(address[0] if isinstance(address, tuple) else address).lower() in {"localhost"}
        return parsed.is_loopback

    def audit(event, arguments):
        if event == "sqlite3.connect" and str(arguments[0]) != ":memory:":
            path = Path(str(arguments[0])).resolve()
            if not any(path.is_relative_to(root) for root in roots):
                raise AssertionError("Regression blocked access to a non-test database")
        elif event == "socket.connect":
            if _is_loopback(arguments[1]):  # (socket, address)
                return
            raise AssertionError("Regression blocked a non-loopback network connection; use a local test double")
        elif event == "socket.getaddrinfo":
            if _is_loopback(arguments[0]):
                return
            raise socket.gaierror("Regression DNS disabled (hostnames blocked; numeric loopback allowed)")

    sys.addaudithook(audit)


@pytest.fixture(autouse=True)
def no_real_ssh_or_key_loading(monkeypatch):
    import paramiko
    def blocked(*args, **kwargs):
        raise AssertionError("Real SSH/private-key loading is forbidden in isolated regression tests")
    monkeypatch.setattr(paramiko.SSHClient, "connect", blocked)
    monkeypatch.setattr(paramiko.Ed25519Key, "from_private_key_file", blocked)


@pytest.fixture()
def control_headers(monkeypatch):
    monkeypatch.setenv("LINUXGUARD_CONTROL_TOKEN", "isolated-regression-token")
    return {"X-Control-Token": "isolated-regression-token"}


@pytest.fixture()
def session_factory(tmp_path):
    db_path = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    testing_session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)
    try:
        yield testing_session_local
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture()
def client(session_factory, monkeypatch):
    from app import main
    monkeypatch.setattr(main, "SessionLocal", session_factory)
    monkeypatch.setattr(main, "init_db", lambda: None)
    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
