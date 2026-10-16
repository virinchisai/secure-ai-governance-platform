from typing import Any

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ClassificationRequest(BaseModel):
    content: str = Field(min_length=1, max_length=100_000)


class SummaryEmailRequest(BaseModel):
    document_ids: list[str] = Field(min_length=1, max_length=20)
    recipient: str = Field(min_length=3, max_length=254)


class ApprovalDecisionRequest(BaseModel):
    approve: bool


class ApprovalExecutionRequest(BaseModel):
    arguments: dict[str, Any]


class SafeQueryRequest(BaseModel):
    query_name: str


class KnowledgeSearchRequest(BaseModel):
    query: str = Field(min_length=2, max_length=2_000)
    limit: int = Field(default=5, ge=1, le=20)
