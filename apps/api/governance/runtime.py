from __future__ import annotations

from dataclasses import dataclass

from .agent import SecureAgent
from .ai import MockAIProvider, OllamaProvider
from .approvals import ApprovalService
from .audit import AuditSink, ForwardingAuditSink, InMemoryAuditSink
from .cache import SemanticCache
from .classification import DataClassifier
from .classifier_adapters import PresidioClassifier
from .config import Settings
from .connectors import GraphProvider, LocalGraphSimulator, MicrosoftGraphProvider, SafeDatabase
from .demo import demo_documents, demo_users
from .dlp import DLPEngine
from .identity import (
    IdentityProvider,
    LocalIdentityProvider,
    MicrosoftEntraProvider,
    OIDCTokenVerifier,
    TokenService,
    TokenVerifier,
)
from .injection import PromptInjectionDetector
from .persistence import DatabaseApprovalStore, DatabaseAuditSink, build_session_factory
from .policy_adapters import OPADLPEngine
from .rag import (
    HashEmbeddingProvider,
    KnowledgeBase,
    KnowledgeChunk,
    LocalKnowledgeBase,
    OllamaEmbeddingProvider,
    PostgresVectorKnowledgeBase,
)
from .rbac import RBACAuthorizer
from .risk import InsiderRiskEngine
from .siem import OpenSearchForwarder


@dataclass
class Runtime:
    identity: IdentityProvider
    tokens: TokenVerifier
    graph: GraphProvider
    classifier: DataClassifier
    dlp: DLPEngine
    approvals: ApprovalService
    audit: AuditSink
    risk: InsiderRiskEngine
    authorizer: RBACAuthorizer
    safe_database: SafeDatabase
    cache: SemanticCache
    knowledge: KnowledgeBase
    agent: SecureAgent


def build_runtime(settings: Settings, *, audit: AuditSink | None = None) -> Runtime:
    graph: GraphProvider
    if settings.graph_provider == "microsoft":
        graph = MicrosoftGraphProvider()
    else:
        graph = LocalGraphSimulator(demo_documents())
    ai = (
        OllamaProvider(settings.ollama_base_url, settings.ollama_model)
        if settings.ai_provider == "ollama"
        else MockAIProvider()
    )
    approval_store = None
    if settings.persistence_mode == "database":
        sessions = build_session_factory(settings.database_url)
        actual_audit = audit or DatabaseAuditSink(settings.database_url, sessions)
        approval_store = DatabaseApprovalStore(settings.database_url, sessions)
    else:
        actual_audit = audit or InMemoryAuditSink()
    if settings.opensearch_url:
        actual_audit = ForwardingAuditSink(
            actual_audit, OpenSearchForwarder(settings.opensearch_url)
        )
    classifier = (
        PresidioClassifier(settings.presidio_url)
        if settings.classifier_provider == "presidio"
        else DataClassifier()
    )
    dlp = OPADLPEngine(settings.opa_url) if settings.policy_provider == "opa" else DLPEngine()
    approvals = ApprovalService(
        settings.jwt_secret.encode(), settings.approval_ttl_minutes, store=approval_store
    )
    risk = InsiderRiskEngine()
    authorizer = RBACAuthorizer()
    cache = SemanticCache(settings.cache_ttl_seconds)
    embeddings = (
        OllamaEmbeddingProvider(settings.ollama_base_url, settings.embedding_model)
        if settings.embedding_provider == "ollama"
        else HashEmbeddingProvider(settings.embedding_dimensions)
    )
    if settings.rag_mode == "postgres" and settings.embedding_dimensions != 768:
        raise ValueError("PostgreSQL vector schema requires EMBEDDING_DIMENSIONS=768")
    knowledge: KnowledgeBase = (
        PostgresVectorKnowledgeBase(settings.database_url, embeddings)
        if settings.rag_mode == "postgres"
        else LocalKnowledgeBase(embeddings)
    )
    if isinstance(graph, LocalGraphSimulator):
        for document in graph.documents:
            knowledge.add(
                KnowledgeChunk(
                    chunk_id=f"{document.workspace_id}:{document.document_id}",
                    workspace_id=document.workspace_id,
                    document_id=document.document_id,
                    content=document.content,
                )
            )
    agent = SecureAgent(
        graph=graph,
        ai=ai,
        classifier=classifier,
        dlp=dlp,
        injection=PromptInjectionDetector(),
        authorizer=authorizer,
        approvals=approvals,
        audit=actual_audit,
        risk=risk,
        cache=cache,
    )
    identity: IdentityProvider
    tokens: TokenVerifier
    if settings.identity_mode == "oidc":
        identity = MicrosoftEntraProvider()
        tokens = OIDCTokenVerifier(
            settings.oidc_issuer, settings.oidc_audience, settings.oidc_jwks_url
        )
    else:
        identity = LocalIdentityProvider(demo_users())
        tokens = TokenService(settings.jwt_secret, settings.jwt_issuer, settings.jwt_ttl_minutes)
    return Runtime(
        identity=identity,
        tokens=tokens,
        graph=graph,
        classifier=classifier,
        dlp=dlp,
        approvals=approvals,
        audit=actual_audit,
        risk=risk,
        authorizer=authorizer,
        safe_database=SafeDatabase(),
        cache=cache,
        knowledge=knowledge,
        agent=agent,
    )
