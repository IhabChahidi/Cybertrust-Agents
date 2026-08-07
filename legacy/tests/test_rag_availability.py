"""ChromaDB unavailable / embedding model unavailable (spec section 12) — RAG
must degrade to 'no context', never crash the Generator."""

import pytest

from mcp_server.rag.chroma_client import ChromaCollections, ChromaUnavailable
from mcp_server.rag.config import RagConfig
from mcp_server.rag.embeddings import EmbeddingBackendUnavailable, SentenceTransformerBackend
from mcp_server.rag.generator_integration import augment_with_rag

pytestmark = pytest.mark.unit


def test_chroma_unavailable_reports_not_available(tmp_path, monkeypatch):
    config = RagConfig(chroma_persist_dir=str(tmp_path / "chroma"))
    chroma = ChromaCollections(config)

    def _boom():
        raise ChromaUnavailable("simulated: no server reachable")
    monkeypatch.setattr(chroma, "_get_client", _boom)

    result = augment_with_rag(request_statement="Is EVD-0001 remediated?", rag_config=config, chroma=chroma)
    assert result.available is False
    assert "ChromaDB" in result.unavailable_reason


def test_embedding_backend_unavailable_is_not_fatal(tmp_path, monkeypatch):
    """A backend whose model can't load (missing dependency, offline, ...) must
    surface EmbeddingBackendUnavailable, not raise something uncatchable. Mocks
    the load failure directly rather than using a real bogus model name, which
    would otherwise make this test do a slow real Hugging Face Hub lookup."""
    config = RagConfig(chroma_persist_dir=str(tmp_path / "chroma"))
    backend = SentenceTransformerBackend(config)
    monkeypatch.setattr(backend, "_load", lambda: (_ for _ in ()).throw(
        EmbeddingBackendUnavailable("simulated: model weights unavailable")
    ))
    assert backend.is_available() is False
    with pytest.raises(EmbeddingBackendUnavailable):
        backend.embed(["some text"])


def test_augment_with_rag_never_raises_on_unexpected_error(tmp_path, monkeypatch):
    config = RagConfig(chroma_persist_dir=str(tmp_path / "chroma"))
    chroma = ChromaCollections(config)

    def _weird_failure(*a, **kw):
        raise RuntimeError("totally unexpected internal error")
    monkeypatch.setattr("mcp_server.rag.generator_integration.retrieve", _weird_failure)

    result = augment_with_rag(request_statement="anything", rag_config=config, chroma=chroma)
    assert result.available is False
    assert "unexpected" in result.unavailable_reason.lower()


def test_generator_proceeds_normally_when_rag_disabled(tmp_path):
    """rag_enabled=False (the default): the Generator must not even attempt to
    import chromadb/sentence-transformers."""
    from mcp_server.config import MCPConfig
    from mcp_server.llm_roles.llama_generator import LlamaGenerator

    config = MCPConfig(llm_mode="llama", journal_path=str(tmp_path / "j.jsonl"))
    assert config.rag_enabled is False
    gen = LlamaGenerator(config)
    assert gen._rag_augmentation("any question") is None
