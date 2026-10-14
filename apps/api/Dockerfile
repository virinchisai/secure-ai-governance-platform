FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN useradd --create-home --uid 10001 appuser
WORKDIR /app
COPY pyproject.toml ./
COPY apps ./apps
RUN pip install --no-cache-dir .
USER appuser
EXPOSE 8000
CMD ["uvicorn", "apps.api.governance.main:app", "--host", "0.0.0.0", "--port", "8000"]
