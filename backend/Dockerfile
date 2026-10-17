# LinuxGuard backend API container (production).
#
# Build context is the REPOSITORY ROOT (see docker-compose.yml): the backend
# reads collector/ scripts at runtime as hash-pinned execution payloads
# (ubuntu_package_maintenance.py, collect_*_asset.sh, openwrt_logread_capture.sh),
# so those files must ship inside the image or collection/repair preflight fails
# with "固定 Collector 不可用" — the classic works-on-dev-host, broken-in-Docker gap.
#
# Boundary note: this container runs the API only. It never loads eBPF, never
# holds device credentials and is deliberately NOT privileged. Real collection
# and Falco/eBPF sensing run on external Linux nodes (pull runner topology).
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# Python UTF-8 模式：保证日志/输出统一 UTF-8（不改变业务数据编码）
ENV PYTHONUTF8=1
ENV PYTHONIOENCODING=utf-8

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn

COPY backend/app ./app
COPY backend/scripts ./scripts
COPY backend/migrations ./migrations
# Hash-pinned collector payloads consumed by app/services (see header).
COPY collector ./collector

# Non-root: the API needs no privileged operations. The data volume inherits
# this ownership when created as a named volume.
RUN useradd --uid 10001 --create-home appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app/data
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=4).status==200 else 1)"]

CMD ["python", "scripts/start_backend.py"]
