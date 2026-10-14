from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from .domain import Document


class ConnectorConfigurationError(RuntimeError):
    pass


class ResourceNotFoundError(LookupError):
    pass


class GraphProvider(ABC):
    @abstractmethod
    def list_users(self, workspace_id: str) -> list[dict[str, str]]: ...

    @abstractmethod
    def list_files(self, workspace_id: str) -> list[Document]: ...

    @abstractmethod
    def read_file(self, workspace_id: str, document_id: str) -> Document: ...

    @abstractmethod
    def list_messages(self, workspace_id: str) -> list[dict[str, str]]: ...

    @abstractmethod
    def create_draft(self, workspace_id: str, recipient: str, subject: str, body: str) -> str: ...

    @abstractmethod
    def send_message(self, workspace_id: str, draft_id: str) -> str: ...


@dataclass
class LocalGraphSimulator(GraphProvider):
    documents: list[Document]

    def __post_init__(self) -> None:
        self.drafts: dict[str, dict[str, str]] = {}
        self.sent_messages: list[dict[str, str]] = []

    def list_users(self, workspace_id: str) -> list[dict[str, str]]:
        return [
            {"id": "local-user", "workspace_id": workspace_id, "display_name": "Local Demo User"}
        ]

    def list_files(self, workspace_id: str) -> list[Document]:
        return [doc for doc in self.documents if doc.workspace_id == workspace_id]

    def read_file(self, workspace_id: str, document_id: str) -> Document:
        for document in self.documents:
            if document.document_id == document_id and document.workspace_id == workspace_id:
                return document
        raise ResourceNotFoundError("Document not found in workspace")

    def list_messages(self, workspace_id: str) -> list[dict[str, str]]:
        return [
            message for message in self.sent_messages if message["workspace_id"] == workspace_id
        ]

    def create_draft(self, workspace_id: str, recipient: str, subject: str, body: str) -> str:
        draft_id = f"draft-{len(self.drafts) + 1}"
        self.drafts[draft_id] = {
            "workspace_id": workspace_id,
            "recipient": recipient,
            "subject": subject,
            "body": body,
        }
        return draft_id

    def send_message(self, workspace_id: str, draft_id: str) -> str:
        draft = self.drafts.get(draft_id)
        if not draft or draft["workspace_id"] != workspace_id:
            raise ResourceNotFoundError("Draft not found in workspace")
        self.sent_messages.append(draft)
        return f"message-{len(self.sent_messages)}"


class MicrosoftGraphProvider(GraphProvider):
    """Integration-ready adapter. Requires a configured Entra application and Graph scopes."""

    def __init__(self) -> None:
        self.tenant_id = os.getenv("AZURE_TENANT_ID")
        self.client_id = os.getenv("AZURE_CLIENT_ID")
        self.client_secret = os.getenv("AZURE_CLIENT_SECRET")
        if not all((self.tenant_id, self.client_id, self.client_secret)):
            raise ConnectorConfigurationError("Microsoft Graph credentials are not configured")

    def _not_live(self) -> None:
        raise ConnectorConfigurationError(
            "Graph HTTP execution requires tenant-specific consent "
            "and is not enabled in the local demo"
        )

    def list_users(self, workspace_id: str) -> list[dict[str, str]]:
        self._not_live()
        return []

    def list_files(self, workspace_id: str) -> list[Document]:
        self._not_live()
        return []

    def read_file(self, workspace_id: str, document_id: str) -> Document:
        self._not_live()
        raise ResourceNotFoundError(document_id)

    def list_messages(self, workspace_id: str) -> list[dict[str, str]]:
        self._not_live()
        return []

    def create_draft(self, workspace_id: str, recipient: str, subject: str, body: str) -> str:
        self._not_live()
        return ""

    def send_message(self, workspace_id: str, draft_id: str) -> str:
        self._not_live()
        return ""


class SafeDatabase:
    ALLOWED_QUERIES = {"document_count", "classification_counts"}

    def query(self, name: str, documents: list[Document]) -> dict[str, Any]:
        if name not in self.ALLOWED_QUERIES:
            raise ValueError("Only named allowlisted queries are permitted")
        if name == "document_count":
            return {"document_count": len(documents)}
        return {"classification_counts": "available through classification endpoint"}
