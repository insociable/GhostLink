FROM python:3.14-slim

ARG POETRY_VERSION=2.4.3

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    GHOSTLINK_CONFIG=/config/ghostlink.toml

RUN pip install "poetry==${POETRY_VERSION}" \
    && groupadd --system ghostlink \
    && useradd --system --gid ghostlink --create-home ghostlink

WORKDIR /app

COPY pyproject.toml poetry.lock README.md LICENSE ./
COPY src ./src

RUN poetry install --only main --no-interaction --no-ansi \
    && mkdir -p /data /config \
    && chown -R ghostlink:ghostlink /app /data /config

USER ghostlink

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).read()" || exit 1

CMD ["ghostnode"]
