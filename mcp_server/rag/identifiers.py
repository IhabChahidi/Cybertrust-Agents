"""Deterministic identifier extraction (spec section 3, extended by the
exact-identifier-routing hardening pass). Used to drive exact-match retrieval
before any vector similarity is attempted, and to validate that a
Generator's citations reference real, retrieved records rather than invented
ones.

A typed representation (`ExtractedIdentifier`/`IdentifierType`) sits
alongside the original dict-shaped `extract_identifiers()` rather than
replacing it: `mcp_server.rag.schemas.RetrievalTrace.identifiers_extracted`
is a `dict[str, list[str]]` already exposed through the public
`/api/v1/retrieval/search` response, and changing its shape would break
compatibility for no benefit. `extract_identifiers()` is now a thin
projection over `extract_typed_identifiers()`, so there is exactly one
extraction/normalization implementation regardless of which shape a caller
wants.
"""

import ipaddress
import re
from enum import Enum

from pydantic import BaseModel

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
MITRE_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
EVIDENCE_ID_RE = re.compile(r"EVD-\d{4}")
RUNBOOK_ID_RE = re.compile(r"RB-[A-Z0-9-]+")

# Candidate patterns for the identifier types that need normalization/validation
# beyond a simple regex match (IP addresses, hashes) -- these are intentionally
# permissive; normalize_identifier() below is the actual gate that accepts or
# rejects a candidate, never the regex alone.
_HOSTNAME_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# IPv6 is deliberately loose here (candidate detection only): full syntactic
# validity, including the "::" compressed-zero shorthand and canonicalization,
# is delegated entirely to Python's `ipaddress` module in normalize_identifier().
_IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}(?:[A-Fa-f0-9]{1,4}|:)\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_CASE_ID_RE = re.compile(r"\bVUL-\d{3,}\b|\bCASE-\d{3,}\b")
_TICKET_ID_RE = re.compile(r"\bSEC-\d{3,}\b|\bTCK-\d{3,}\b")
_ASSET_ID_RE = re.compile(r"\bSRV-[A-Z0-9-]+\b")

# Kept for backward compatibility: callers that used EXTRA_PATTERNS directly
# (pre-typed-identifier code) still get the same dict of compiled patterns.
EXTRA_PATTERNS: dict[str, re.Pattern] = {
    "case_id": _CASE_ID_RE,
    "ticket_id": _TICKET_ID_RE,
    "asset_id": _ASSET_ID_RE,
    "hostname": _HOSTNAME_RE,
    "ipv4": _IPV4_RE,
    "ipv6": _IPV6_RE,
    "sha256": _SHA256_RE,
    "sha1": _SHA1_RE,
    "md5": _MD5_RE,
}

_CORE_PATTERNS: dict[str, re.Pattern] = {
    "cve_id": CVE_RE,
    "mitre_technique": MITRE_TECHNIQUE_RE,
    "evidence_id": EVIDENCE_ID_RE,
    "runbook_id": RUNBOOK_ID_RE,
}


# ChromaDB metadata values must be scalar in the installed version (1.5.9) --
# there is no reliable way to store a list and later run an exact `where`
# equality match against one of several values inside it. A record with
# multiple IPs/hashes stores them across this many fixed, indexed scalar
# columns (e.g. ip_address_0.._4) instead -- a deterministic, documented
# serialized representation. See mcp_server/rag/ingestion.py (writer) and
# mcp_server/rag/retrieval.py (reader) for the two call sites.
MAX_INDEXED_IDENTIFIER_VALUES = 5


class IdentifierType(str, Enum):
    CVE_ID = "cve_id"
    MITRE_TECHNIQUE = "mitre_technique"
    EVIDENCE_ID = "evidence_id"
    RUNBOOK_ID = "runbook_id"
    CASE_ID = "case_id"
    TICKET_ID = "ticket_id"
    ASSET_ID = "asset_id"
    HOSTNAME = "hostname"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"


# Routing target for each identifier type (spec: "Required routing rules").
# CVE/MITRE/runbook route to their own dedicated reference collection;
# everything else that can appear on a corporate evidence record routes there.
IDENTIFIER_COLLECTION: dict[IdentifierType, str] = {
    IdentifierType.CVE_ID: "vulnerabilities",
    IdentifierType.MITRE_TECHNIQUE: "mitre_attack",
    IdentifierType.RUNBOOK_ID: "runbooks",
    IdentifierType.EVIDENCE_ID: "corporate_evidence",
    IdentifierType.CASE_ID: "corporate_evidence",
    IdentifierType.TICKET_ID: "corporate_evidence",
    IdentifierType.ASSET_ID: "corporate_evidence",
    IdentifierType.HOSTNAME: "corporate_evidence",
    IdentifierType.IPV4: "corporate_evidence",
    IdentifierType.IPV6: "corporate_evidence",
    IdentifierType.SHA256: "corporate_evidence",
    IdentifierType.SHA1: "corporate_evidence",
    IdentifierType.MD5: "corporate_evidence",
}

_PATTERNS_BY_TYPE: dict[IdentifierType, re.Pattern] = {
    IdentifierType.CVE_ID: CVE_RE,
    IdentifierType.MITRE_TECHNIQUE: MITRE_TECHNIQUE_RE,
    IdentifierType.EVIDENCE_ID: EVIDENCE_ID_RE,
    IdentifierType.RUNBOOK_ID: RUNBOOK_ID_RE,
    IdentifierType.CASE_ID: _CASE_ID_RE,
    IdentifierType.TICKET_ID: _TICKET_ID_RE,
    IdentifierType.ASSET_ID: _ASSET_ID_RE,
    IdentifierType.HOSTNAME: _HOSTNAME_RE,
    IdentifierType.IPV4: _IPV4_RE,
    IdentifierType.IPV6: _IPV6_RE,
    IdentifierType.SHA256: _SHA256_RE,
    IdentifierType.SHA1: _SHA1_RE,
    IdentifierType.MD5: _MD5_RE,
}

# IPv4 addresses are also valid matches for the (looser) IPv6 candidate
# pattern is not a concern here since the patterns share no character
# classes that would cross-match; the real overlap risk is SHA-1/MD5/SHA-256
# hex strings vs each other, which _typed_candidates() resolves by length
# (each hash regex is anchored to an exact hex-digit count, so a given
# token can only ever match one of the three).
_TRIM_PUNCTUATION = ".,;:()[]{}'\"<>"


class ExtractedIdentifier(BaseModel):
    """One normalized, validated identifier occurrence (spec: "Implement a
    typed identifier representation"). `value` is the raw matched text
    (trimmed of surrounding punctuation only); `normalized_value` is what
    retrieval/storage actually key on -- e.g. a canonical `ipaddress` string,
    a lowercased hash, an uppercased CVE/MITRE id.
    """

    type: IdentifierType
    value: str
    normalized_value: str


def normalize_identifier(id_type: IdentifierType, raw_value: str) -> str | None:
    """Returns the normalized value, or None if `raw_value` is not actually a
    valid instance of `id_type` (spec: "reject malformed identifiers") --
    callers must drop the candidate entirely on None, never fall back to the
    raw text.
    """
    value = (raw_value or "").strip().strip(_TRIM_PUNCTUATION)
    if not value:
        return None

    if id_type in (IdentifierType.CVE_ID, IdentifierType.MITRE_TECHNIQUE):
        return value.upper()

    if id_type == IdentifierType.HOSTNAME:
        return value.rstrip(".").lower()

    if id_type in (IdentifierType.IPV4, IdentifierType.IPV6):
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    if id_type in (IdentifierType.SHA256, IdentifierType.SHA1, IdentifierType.MD5):
        if not re.fullmatch(r"[a-fA-F0-9]+", value):
            return None
        expected_len = {IdentifierType.SHA256: 64, IdentifierType.SHA1: 40, IdentifierType.MD5: 32}[id_type]
        if len(value) != expected_len:
            return None
        return value.lower()

    # evidence_id / runbook_id / case_id / ticket_id / asset_id: these are
    # already normalized by construction (fixed-shape regexes), no case
    # folding applied since these ids are used verbatim as Chroma record ids
    # / exact metadata values elsewhere in the codebase.
    return value


def extract_typed_identifiers(text: str) -> list[ExtractedIdentifier]:
    """Returns every validated identifier occurrence found in `text`, in no
    particular order, deduplicated by (type, normalized_value). Never raises
    on malformed/empty text -- a candidate that fails normalize_identifier()
    is silently dropped, not surfaced as an error (the string simply wasn't a
    real instance of that identifier type).
    """
    text = text or ""
    seen: set[tuple[IdentifierType, str]] = set()
    results: list[ExtractedIdentifier] = []
    for id_type, pattern in _PATTERNS_BY_TYPE.items():
        for raw_match in pattern.findall(text):
            normalized = normalize_identifier(id_type, raw_match)
            if normalized is None:
                continue
            key = (id_type, normalized)
            if key in seen:
                continue
            seen.add(key)
            results.append(ExtractedIdentifier(type=id_type, value=raw_match, normalized_value=normalized))
    return results


def extract_identifiers(text: str, *, extra_patterns: dict[str, re.Pattern] | None = None) -> dict[str, list[str]]:
    """Returns {identifier_type: [normalized_matches...]} -- the legacy
    dict shape, preserved for backward compatibility (RetrievalTrace,
    existing call sites). Built from extract_typed_identifiers() so there is
    a single extraction/normalization implementation; `extra_patterns`, when
    given, is used INSTEAD of the built-in type table (matching the original
    function's contract) and bypasses normalization (raw regex matches only),
    since a caller-supplied pattern has no known IdentifierType to normalize
    against.
    """
    if extra_patterns is not None:
        text = text or ""
        patterns = {**_CORE_PATTERNS, **extra_patterns}
        out: dict[str, list[str]] = {}
        for name, pattern in patterns.items():
            matches = sorted(set(pattern.findall(text)))
            if matches:
                out[name] = matches
        return out

    grouped: dict[str, set[str]] = {}
    for identifier in extract_typed_identifiers(text):
        grouped.setdefault(identifier.type.value, set()).add(identifier.normalized_value)
    return {name: sorted(values) for name, values in grouped.items()}
