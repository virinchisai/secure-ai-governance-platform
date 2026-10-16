from apps.api.governance.rag import HashEmbeddingProvider, KnowledgeChunk, LocalKnowledgeBase


def test_knowledge_search_filters_workspace_before_scoring() -> None:
    knowledge = LocalKnowledgeBase(HashEmbeddingProvider(64))
    knowledge.add(
        KnowledgeChunk(
            chunk_id="tenant-a:1",
            workspace_id="tenant-a",
            document_id="1",
            content="ordinary internal memo",
        )
    )
    knowledge.add(
        KnowledgeChunk(
            chunk_id="tenant-b:secret",
            workspace_id="tenant-b",
            document_id="secret",
            content="exact unique target phrase",
        )
    )

    results = knowledge.search("tenant-a", "exact unique target phrase")

    assert results
    assert {item.workspace_id for item in results} == {"tenant-a"}
    assert all(item.document_id != "secret" for item in results)


def test_hash_embeddings_are_deterministic() -> None:
    embeddings = HashEmbeddingProvider(64)

    assert embeddings.embed("same safe query") == embeddings.embed("same safe query")


def test_knowledge_search_limit_is_enforced() -> None:
    knowledge = LocalKnowledgeBase(HashEmbeddingProvider(64))
    for index in range(4):
        knowledge.add(
            KnowledgeChunk(
                chunk_id=f"tenant-a:{index}",
                workspace_id="tenant-a",
                document_id=str(index),
                content=f"document {index}",
            )
        )

    assert len(knowledge.search("tenant-a", "document", limit=2)) == 2
