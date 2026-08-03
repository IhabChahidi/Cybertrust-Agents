"""Embedding abstraction (spec section 1: "so the embedding model can be
replaced later"). Real production backend is SentenceTransformerBackend, local
and CPU-only, no external embedding API. A deterministic hash-based backend is
also provided for tests and for environments where sentence-transformers/torch
are not installed — it is NOT semantically meaningful and must never be used in
production; it exists purely so unit tests run fast and without a multi-hundred
MB model download (see tests/test_rag_*.py).
"""

from abc import ABC, abstractmethod
from hashlib import blake2b

from mcp_server.rag.config import RagConfig


class EmbeddingBackendUnavailable(RuntimeError):
    """Raised when a backend's dependency (sentence-transformers, torch, the
    model weights, ...) is not installed/reachable. Callers must catch this and
    degrade gracefully (RAG retrieval unavailable), never crash the pipeline."""


class EmbeddingBackend(ABC):
    dimension: int

    @abstractmethod
    def embed(self, texts: list[str]) -> list[list[float]]:
        """Return one embedding vector per input text, same order."""
        raise NotImplementedError

    @abstractmethod
    def is_available(self) -> bool:
        raise NotImplementedError


class SentenceTransformerBackend(EmbeddingBackend):
    """Local sentence-transformers model (default: BAAI/bge-small-en-v1.5, 384-dim).
    Lazily imports sentence_transformers so this module (and everything that
    imports it) can be imported even when the package isn't installed.
    """

    def __init__(self, config: RagConfig):
        self.config = config
        self.dimension = 384  # bge-small-en-v1.5's known output dimension
        self._model = None

    def _load(self):
        if self._model is not None:
            return self._model
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise EmbeddingBackendUnavailable(
                "sentence-transformers is not installed; RAG vector retrieval is unavailable. "
                "Install with `pip install sentence-transformers`."
            ) from exc
        try:
            self._model = SentenceTransformer(self.config.embedding_model, device=self.config.embedding_device)
        except Exception as exc:  # model download/load failure, offline, corrupt cache, ...
            raise EmbeddingBackendUnavailable(
                f"failed to load embedding model {self.config.embedding_model!r}: {exc}"
            ) from exc
        return self._model

    def is_available(self) -> bool:
        try:
            self._load()
            return True
        except EmbeddingBackendUnavailable:
            return False

    def embed(self, texts: list[str]) -> list[list[float]]:
        model = self._load()
        vectors = model.encode(
            texts, batch_size=self.config.embedding_batch_size,
            convert_to_numpy=True, normalize_embeddings=True,
        )
        return [v.tolist() for v in vectors]


class DeterministicHashEmbeddingBackend(EmbeddingBackend):
    """Test/dev-only fallback: a fixed-dimension hashing-trick bag-of-words
    vector. Deterministic and dependency-free, but NOT a semantic embedding --
    never wire this into a production retrieval path. Its only job is to let
    the retrieval/fusion/context-builder logic be tested without a model
    download, and to keep the RAG layer importable/testable in environments
    where torch/sentence-transformers are unavailable.
    """

    def __init__(self, dimension: int = 384):
        self.dimension = dimension

    def is_available(self) -> bool:
        return True

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._vector(t) for t in texts]

    def _vector(self, text: str) -> list[float]:
        vec = [0.0] * self.dimension
        for token in (text or "").lower().split():
            h = int.from_bytes(blake2b(token.encode("utf-8"), digest_size=4).digest(), "big")
            vec[h % self.dimension] += 1.0
        norm = sum(v * v for v in vec) ** 0.5
        if norm > 0:
            vec = [v / norm for v in vec]
        return vec


def get_embedding_backend(config: RagConfig, *, force_fake: bool = False) -> EmbeddingBackend:
    """Factory: real backend by default, deterministic fallback only when
    force_fake=True (tests) — production code paths never silently fall back to
    the fake backend, so a missing dependency in production is loud (see
    retrieval.py, which surfaces EmbeddingBackendUnavailable rather than
    swallowing it into a fake, misleading result set).
    """
    if force_fake:
        return DeterministicHashEmbeddingBackend()
    return SentenceTransformerBackend(config)
