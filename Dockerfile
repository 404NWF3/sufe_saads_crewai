# Unified runtime: intel_agent + ctinexus_kg + Gradio console.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend \
    GRADIO_SERVER_NAME=0.0.0.0 \
    GRADIO_SERVER_PORT=8000 \
    IS_SANDBOX=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm install -g @anthropic-ai/claude-code \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY backend ./backend

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
        "claude-agent-sdk>=0.2.113" \
        "pydantic>=2.7" \
        "pymongo>=4.6" \
        "ctinexus==0.2.1" \
        "gradio>=5.0.0,<6.0.0"

EXPOSE 8000

CMD ["python", "-m", "console.app"]
