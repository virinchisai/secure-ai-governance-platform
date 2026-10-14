from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from apps.api.governance.config import Settings
from apps.api.governance.domain import Role, UserContext
from apps.api.governance.main import create_app
from apps.api.governance.runtime import build_runtime


@pytest.fixture
def settings() -> Settings:
    return Settings(environment="test", jwt_secret="test-secret-that-is-at-least-32-characters")


@pytest.fixture
def runtime(settings: Settings):
    return build_runtime(settings)


@pytest.fixture
def analyst() -> UserContext:
    return UserContext(
        user_id="user-analyst", workspace_id="acme-labs", roles=frozenset({Role.ANALYST})
    )


@pytest.fixture
def compliance() -> UserContext:
    return UserContext(
        user_id="user-compliance",
        workspace_id="acme-labs",
        roles=frozenset({Role.COMPLIANCE_ADMIN}),
    )


@pytest.fixture
def client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings))


def login(
    client: TestClient, username: str = "analyst@acme.test", password: str = "Demo-Analyst-2026!"
) -> dict[str, str]:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}
