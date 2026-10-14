from __future__ import annotations

import base64
import hashlib
import hmac
import os
from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta

import jwt

from .domain import Role, UserContext, UserRecord


class AuthenticationError(ValueError):
    pass


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    actual_salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), actual_salt, 600_000)
    salt_value = base64.b64encode(actual_salt).decode()
    digest_value = base64.b64encode(digest).decode()
    return f"pbkdf2_sha256$600000${salt_value}${digest_value}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt_text, expected_text = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_text)
        expected = base64.b64decode(expected_text)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


class IdentityProvider(ABC):
    @abstractmethod
    def authenticate(self, username: str, password: str) -> UserContext: ...


class LocalIdentityProvider(IdentityProvider):
    def __init__(self, users: list[UserRecord]) -> None:
        self._users = {user.username: user for user in users}

    def authenticate(self, username: str, password: str) -> UserContext:
        user = self._users.get(username)
        if not user or not user.active or not verify_password(password, user.password_hash):
            raise AuthenticationError("Invalid credentials")
        return UserContext(user_id=user.user_id, workspace_id=user.workspace_id, roles=user.roles)


class MicrosoftEntraProvider(IdentityProvider):
    """OIDC integration seam; requires tenant metadata and token-validation configuration."""

    def authenticate(self, username: str, password: str) -> UserContext:
        raise AuthenticationError(
            "Direct password authentication is disabled for Microsoft Entra; "
            "configure OIDC authorization code flow"
        )


class TokenService:
    def __init__(self, secret: str, issuer: str, ttl_minutes: int = 60) -> None:
        self.secret = secret
        self.issuer = issuer
        self.ttl = timedelta(minutes=ttl_minutes)

    def issue(self, context: UserContext) -> str:
        now = datetime.now(UTC)
        return jwt.encode(
            {
                "sub": context.user_id,
                "workspace_id": context.workspace_id,
                "roles": sorted(role.value for role in context.roles),
                "iss": self.issuer,
                "iat": now,
                "exp": now + self.ttl,
            },
            self.secret,
            algorithm="HS256",
        )

    def verify(self, token: str) -> UserContext:
        try:
            payload = jwt.decode(token, self.secret, algorithms=["HS256"], issuer=self.issuer)
            return UserContext(
                user_id=str(payload["sub"]),
                workspace_id=str(payload["workspace_id"]),
                roles=frozenset(Role(role) for role in payload["roles"]),
            )
        except (jwt.PyJWTError, KeyError, ValueError) as exc:
            raise AuthenticationError("Invalid or expired token") from exc
