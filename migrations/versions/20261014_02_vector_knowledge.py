"""Add tenant-isolated pgvector knowledge chunks."""

from alembic import op

revision = "20261014_02"
down_revision = "20261014_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute(
        """CREATE TABLE knowledge_chunks (
        chunk_id VARCHAR(128) PRIMARY KEY,
        workspace_id VARCHAR(64) NOT NULL,
        document_id VARCHAR(128) NOT NULL,
        content TEXT NOT NULL,
        embedding vector(768) NOT NULL
        )"""
    )
    op.execute("CREATE INDEX ix_knowledge_workspace ON knowledge_chunks (workspace_id)")
    op.execute(
        "CREATE INDEX ix_knowledge_embedding ON knowledge_chunks "
        "USING hnsw (embedding vector_cosine_ops)"
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TABLE IF EXISTS knowledge_chunks")
