"""Exercises the REAL SentenceTransformerBackend (BAAI/bge-small-en-v1.5) against
a real local ChromaDB. Not part of the fast unit/integration suite: downloads
~130MB of model weights on first run (one-time, then cached under
~/.cache/huggingface). Skipped automatically if that download/load fails for
any reason (offline, disk space, ...) rather than failing the suite.

Run explicitly with: py -m pytest tests/test_rag_real_embeddings.py -v
"""

import pytest

from mcp_server.rag.config import RagConfig
from mcp_server.rag.embeddings import SentenceTransformerBackend

pytestmark = pytest.mark.rag_model


@pytest.fixture(scope="module")
def real_backend():
    backend = SentenceTransformerBackend(RagConfig())
    if not backend.is_available():
        pytest.skip("real embedding model unavailable in this environment (offline or load failure)")
    return backend


def test_real_backend_produces_384_dim_normalized_vectors(real_backend):
    vectors = real_backend.embed(["The ticket was closed with a valid patch report."])
    assert len(vectors) == 1
    assert len(vectors[0]) == 384
    norm = sum(v * v for v in vectors[0]) ** 0.5
    assert abs(norm - 1.0) < 0.01  # normalize_embeddings=True


def test_real_backend_semantic_similarity_is_higher_for_related_text(real_backend):

    def cosine(a, b):
        return sum(x * y for x, y in zip(a, b))  # already normalized, so dot product == cosine

    vecs = real_backend.embed([
        "The critical vulnerability was remediated and verified by a rescan.",
        "The patch for the security flaw was applied and confirmed clean.",
        "The quarterly marketing budget was approved by finance.",
    ])
    related_score = cosine(vecs[0], vecs[1])
    unrelated_score = cosine(vecs[0], vecs[2])
    assert related_score > unrelated_score
