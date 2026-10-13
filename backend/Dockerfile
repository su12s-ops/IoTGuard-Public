FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# Python UTF-8 模式：保证日志/输出统一 UTF-8（不改变业务数据编码）
ENV PYTHONUTF8=1
ENV PYTHONIOENCODING=utf-8

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn

COPY app ./app
COPY scripts ./scripts

EXPOSE 8000

CMD ["python", "scripts/start_backend.py"]
