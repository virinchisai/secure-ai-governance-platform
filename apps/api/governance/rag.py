from __future__ import annotations

import hashlib
import math
from abc import ABC, abstractmethod
from typing import Protocol

import httpx
from pydantic import BaseModel
from sqlalchemy import create_engine, text


class KnowledgeChunk(BaseModel):
    chunk_id: str
    workspace_id: str
    document_id: str
    content: str
    score: float = 0


class EmbeddingProvider(Protocol):
    def embed(self, text: str) -> list[float]: ...


class HashEmbeddingProvider:
    """Deterministic local test embedding; no semantic quality claim is made."""

    def __init__(self, dimensions: int = 768) -> None:
        self.dimensions = dimensions

    def embed(self, text: str) -> list[float]:
        values = [0.0] * self.dimensions
        for token in text.lower().split():
            digest = hashlib.sha256(token.encode()).digest()
            index = int.from_bytes(digest[:4], "big") % self.dimensions
            values[index] += -1.0 if digest[4] & 1 else 1.0
        norm = math.sqrt(sum(value * value for value in values)) or 1.0
        return [value / norm for value in values]


class OllamaEmbeddingProvider:
    def __init__(self, base_url: str, model: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model

    def embed(self, text_value: str) -> list[float]:
        response = httpx.post(
            f"{self.base_url}/api/embed",
            json={"model": self.model, "input": text_value},
            timeout=60,
        )
        response.raise_for_status()
        return [float(value) for value in response.json()["embeddings"][0]]


class KnowledgeBase(ABC):
    @abstractmethod
    def add(self, chunk: KnowledgeChunk) -> None: ...

    @abstractmethod
    def search(self, workspace_id: str, query: str, limit: int = 5) -> list[KnowledgeChunk]: ...


class LocalKnowledgeBase(KnowledgeBase):
    def __init__(self, embeddings: EmbeddingProvider) -> None:
        self.embeddings = embeddings
        self._chunks: dict[str, tuple[KnowledgeChunk, list[float]]] = {}

    def add(self, chunk: KnowledgeChunk) -> None:
        self._chunks[chunk.chunk_id] = (chunk, self.embeddings.embed(chunk.content))

    def search(self, workspace_id: str, query: str, limit: int = 5) -> list[KnowledgeChunk]:
        query_vector = self.embeddings.embed(query)
        scored = []
        for chunk, vector in self._chunks.values():
            if chunk.workspace_id != workspace_id:
                continue
            score = sum(left * right for left, right in zip(query_vector, vector, strict=True))
            scored.append(chunk.model_copy(update={"score": score}))
        return sorted(scored, key=lambda item: item.score, reverse=True)[:limit]


class PostgresVectorKnowledgeBase(KnowledgeBase):
    def __init__(self, database_url: str, embeddings: EmbeddingProvider) -> None:
        self.engine = create_engine(database_url)
        self.embeddings = embeddings

    @staticmethod
    def _vector(values: list[float]) -> str:
        return "[" + ",".join(f"{value:.8f}" for value in values) + "]"

    def add(self, chunk: KnowledgeChunk) -> None:
        embedding = self._vector(self.embeddings.embed(chunk.content))
        with self.engine.begin() as connection:
            connection.execute(
                text(
                    """INSERT INTO knowledge_chunks
                    (chunk_id, workspace_id, document_id, content, embedding)
                    VALUES (
                        :chunk_id, :workspace_id, :document_id, :content,
                        CAST(:embedding AS vector)
                    )
                    ON CONFLICT (chunk_id) DO UPDATE SET content = EXCLUDED.content,
                    embedding = EXCLUDED.embedding"""
                ),
                {**chunk.model_dump(exclude={"score"}), "embedding": embedding},
            )

    def search(self, workspace_id: str, query: str, limit: int = 5) -> list[KnowledgeChunk]:
        embedding = self._vector(self.embeddings.embed(query))
        with self.engine.connect() as connection:
            rows = connection.execute(
                text(
                    """SELECT chunk_id, workspace_id, document_id, content,
                    1 - (embedding <=> CAST(:embedding AS vector)) AS score
                    FROM knowledge_chunks WHERE workspace_id = :workspace_id
                    ORDER BY embedding <=> CAST(:embedding AS vector) LIMIT :limit"""
                ),
                {"embedding": embedding, "workspace_id": workspace_id, "limit": limit},
            ).mappings()
            return [KnowledgeChunk.model_validate(dict(row)) for row in rows]
