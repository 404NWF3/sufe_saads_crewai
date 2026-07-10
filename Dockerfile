FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GRADIO_SERVER_NAME=0.0.0.0 \
    GRADIO_SERVER_PORT=8000

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
# pyproject's wheel packages list includes backend/intel_agent, so hatchling
# needs it present in the build context even though this image runs the web app.
COPY backend ./backend

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

EXPOSE 8000

CMD ["python", "-m", "sufe_saads_crewai.web.app"]
