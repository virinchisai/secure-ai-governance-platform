from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from uuid import uuid4

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from .api import router
from .config import Settings, get_settings
from .runtime import build_runtime

REQUESTS = Counter("governance_http_requests_total", "HTTP requests", ["method", "path", "status"])
LATENCY = Histogram(
    "governance_http_request_duration_seconds", "HTTP request latency", ["method", "path"]
)
logger = structlog.get_logger("governance.api")


def create_app(settings: Settings | None = None) -> FastAPI:
    actual_settings = settings or get_settings()
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )
    app = FastAPI(
        title="Secure AI Governance Platform",
        version="0.1.0",
        description="Local-first AI security controls with simulated enterprise connectors.",
    )
    app.state.runtime = build_runtime(actual_settings)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid4()))[:64]
        request.state.request_id = request_id
        started = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("request_failed", request_id=request_id, path=request.url.path)
            raise
        elapsed = time.monotonic() - started
        route = request.url.path
        REQUESTS.labels(request.method, route, str(response.status_code)).inc()
        LATENCY.labels(request.method, route).observe(elapsed)
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "request_complete",
            request_id=request_id,
            method=request.method,
            path=route,
            status=response.status_code,
            duration_ms=round(elapsed * 1000, 2),
        )
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {
            "status": "ok",
            "mode": actual_settings.environment,
            "graph": actual_settings.graph_provider,
            "ai": actual_settings.ai_provider,
        }

    @app.get("/metrics", include_in_schema=False)
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    app.include_router(router)
    return app


app = create_app()
