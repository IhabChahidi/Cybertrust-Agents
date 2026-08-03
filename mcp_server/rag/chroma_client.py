"""ChromaDB client wrapper. Manages exactly the four controlled collections
(mcp_server.rag.config.ALL_COLLECTIONS) — no caller, API client, or LLM output
can create or query an arbitrary collection name; every method here validates
against that fixed set (spec section 2).

Lazily imports chromadb so the rest of the RAG package (and the Generator that
uses it) remains importable even when chromadb is not installed or the local
store cannot be opened -- callers must catch ChromaUnavailable and degrade to
"no RAG context", never crash the pipeline.
"""

from pathlib import Path
from typing import Any

from mcp_server.rag.config import ALL_COLLECTIONS, RagConfig


class ChromaUnavailable(RuntimeError):
    """Raised when chromadb is not installed, or the configured store (local
    path or remote host) cannot be reached/opened."""


class ChromaCollections:
    """Thin, validated wrapper around a chromadb client's collection access.

    We manage embeddings ourselves (mcp_server.rag.embeddings) and pass raw
    vectors to Chroma rather than letting Chroma compute its own embeddings —
    this is what makes the embedding backend swappable independently of the
    vector store, per the spec's "create an embedding abstraction" requirement.
    """

    def __init__(self, config: RagConfig):
        self.config = config
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            import chromadb
        except ImportError as exc:
            raise ChromaUnavailable(
                "chromadb is not installed; RAG retrieval/ingestion is unavailable. "
                "Install with `pip install chromadb`."
            ) from exc

        try:
            if self.config.chroma_host:
                self._client = chromadb.HttpClient(
                    host=self.config.chroma_host, port=self.config.chroma_port,
                    tenant=self.config.chroma_tenant, database=self.config.chroma_database,
                )
            else:
                # No Chroma server in this environment (no Docker) -- default to
                # a local, on-disk persistent store. Functionally identical
                # collection API either way.
                Path(self.config.chroma_persist_dir).mkdir(parents=True, exist_ok=True)
                self._client = chromadb.PersistentClient(path=self.config.chroma_persist_dir)
        except Exception as exc:
            raise ChromaUnavailable(f"failed to connect to ChromaDB: {exc}") from exc
        return self._client

    def is_available(self) -> bool:
        try:
            client = self._get_client()
            client.heartbeat()
            return True
        except Exception:
            return False

    def _validate_collection(self, name: str) -> None:
        if name not in ALL_COLLECTIONS:
            raise ValueError(f"unknown collection {name!r}; must be one of {sorted(ALL_COLLECTIONS)}")

    def get_or_create(self, name: str):
        self._validate_collection(name)
        client = self._get_client()
        # embedding_function=None: we always supply pre-computed vectors
        # ourselves (see upsert/query below), never let Chroma pick its own
        # embedding model implicitly.
        return client.get_or_create_collection(name=name, embedding_function=None)

    def upsert(self, *, collection: str, ids: list[str], embeddings: list[list[float]],
               documents: list[str], metadatas: list[dict[str, Any]]) -> None:
        self._validate_collection(collection)
        coll = self.get_or_create(collection)
        coll.upsert(ids=ids, embeddings=embeddings, documents=documents, metadatas=metadatas)

    def query(self, *, collection: str, query_embedding: list[float], n_results: int,
              where: dict[str, Any] | None = None) -> dict[str, Any]:
        self._validate_collection(collection)
        coll = self.get_or_create(collection)
        return coll.query(query_embeddings=[query_embedding], n_results=n_results, where=where or None)

    def get_by_ids(self, *, collection: str, ids: list[str]) -> dict[str, Any]:
        self._validate_collection(collection)
        coll = self.get_or_create(collection)
        return coll.get(ids=ids)

    def get_by_where(self, *, collection: str, where: dict[str, Any], limit: int | None = None) -> dict[str, Any]:
        self._validate_collection(collection)
        coll = self.get_or_create(collection)
        return coll.get(where=where, limit=limit)

    def count(self, *, collection: str) -> int:
        self._validate_collection(collection)
        return self.get_or_create(collection).count()
