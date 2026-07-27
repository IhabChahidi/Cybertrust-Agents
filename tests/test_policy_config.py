"""Workstream B: configuration-driven business exceptions (mcp_server/policy_config.py)
and their hard invariants (mcp_server/policy.py). Covers spec sections 4.2 and 7.4:
malicious/invalid configurations must never bypass a governance invariant.
"""

import textwrap

import pytest

from mcp_server.policy import PolicyInputError, decide
from mcp_server.policy_config import DEFAULT_CONFIG_PATH, PolicyConfigError, load_policy_config

pytestmark = pytest.mark.unit


def _vr(status, **overrides):
    base = {
        "id": "VER-0001", "status": status, "reasoning_summary": "r",
        "supporting_evidence": ["EVD-0001"], "contradicting_evidence": [], "missing_evidence": [],
    }
    base.update(overrides)
    return base


def _score(risk_level, value=50):
    return {"id": "MCP-SCORE-0001", "value": value, "risk_level": risk_level}


def _decide(status, risk_level, config_path=None):
    return decide(
        verification_result=_vr(status), mcp_score=_score(risk_level),
        decision_id="VAL-0001", session_id="SES-TEST0000", correlation_id="COR-TEST0000",
        policy_config_path=config_path,
    )


def _write_config(tmp_path, yaml_text):
    path = tmp_path / "policy_rules.yaml"
    path.write_text(textwrap.dedent(yaml_text), encoding="utf-8")
    return str(path)


# -- the shipped config loads and validates cleanly ---------------------------

def test_shipped_default_config_loads_and_validates():
    config = load_policy_config(DEFAULT_CONFIG_PATH)
    assert config["policy_version"] == "1.1"
    assert len(config["rules"]) >= 2


def test_shipped_config_reproduces_default_routing_via_decide():
    result = _decide("supported", "HIGH", config_path=str(DEFAULT_CONFIG_PATH))
    assert result["decision"] == "READY_FOR_CISO_DECISION"
    assert result["applied_exception"] is True  # POL-001 matched
    assert result["policy_rule"] == "POL-001"
    assert result["policy_version"] == "1.1"
    assert "configuration_hash" in result


# -- malformed configuration fails closed --------------------------------------

def test_malformed_yaml_fails_closed_to_default_table(tmp_path):
    path = _write_config(tmp_path, "policy_version: '1.0'\nrules: [this is not: valid: yaml: at all")
    with pytest.raises(PolicyConfigError):
        load_policy_config(path)
    # decide() itself must not crash even though the config is broken -- it logs
    # and falls back to the built-in default table.
    result = _decide("contradicted", "LOW", config_path=path)
    assert result["decision"] == "READY_FOR_CISO_DECISION"
    assert result["applied_exception"] is False
    assert "policy_version" not in result  # no valid config was ever loaded


def test_empty_rules_list_is_valid_but_matches_nothing(tmp_path):
    path = _write_config(tmp_path, """
        policy_version: "1.0"
        rules: []
    """)
    config = load_policy_config(path)
    assert config["rules"] == []
    result = _decide("supported", "HIGH", config_path=path)
    assert result["decision"] == "READY_FOR_CISO_DECISION"  # built-in default still applies
    assert result["applied_exception"] is False


def test_rule_attempting_human_review_action_is_rejected_at_load(tmp_path):
    path = _write_config(tmp_path, """
        policy_version: "1.0"
        rules:
          - id: "POL-100"
            enabled: true
            priority: 1
            match: {verification_status: "contradicted"}
            action: {decision: "HUMAN_REVIEW", requires_ciso_approval: true}
            reason: "malicious"
    """)
    with pytest.raises(PolicyConfigError):
        load_policy_config(path)


def test_rule_with_unsupported_action_value_is_rejected_at_load(tmp_path):
    path = _write_config(tmp_path, """
        policy_version: "1.0"
        rules:
          - id: "POL-101"
            enabled: true
            priority: 1
            match: {verification_status: "supported"}
            action: {decision: "SOMETHING_MADE_UP", requires_ciso_approval: true}
            reason: "invalid"
    """)
    with pytest.raises(PolicyConfigError):
        load_policy_config(path)


def test_rule_matching_insufficient_evidence_status_is_rejected_at_load(tmp_path):
    """insufficient_evidence is not even an offerable match value -- a rule
    naming it fails schema validation, closing the "MCPScore compensates for
    missing evidence" door at the config layer too."""
    path = _write_config(tmp_path, """
        policy_version: "1.0"
        rules:
          - id: "POL-102"
            enabled: true
            priority: 1
            match: {verification_status: "insufficient_evidence"}
            action: {decision: "READY_FOR_CISO_INFORMATION", requires_ciso_approval: false}
            reason: "attempt to compensate for missing evidence"
    """)
    with pytest.raises(PolicyConfigError):
        load_policy_config(path)


def test_duplicate_rule_ids_rejected(tmp_path):
    path = _write_config(tmp_path, """
        policy_version: "1.0"
        rules:
          - id: "POL-001"
            enabled: true
            priority: 1
            match: {verification_status: "supported"}
            action: {decision: "READY_FOR_CISO_DECISION", requires_ciso_approval: true}
            reason: "a"
          - id: "POL-001"
            enabled: true
            priority: 2
            match: {verification_status: "unsupported"}
            action: {decision: "REJECTED", requires_ciso_approval: false}
            reason: "b"
    """)
    with pytest.raises(PolicyConfigError):
        load_policy_config(path)


def test_duplicate_priorities_for_overlapping_rules_rejected(tmp_path):
    path = _write_config(tmp_path, """
        policy_version: "1.0"
        rules:
          - id: "POL-001"
            enabled: true
            priority: 10
            match: {verification_status: "supported"}
            action: {decision: "READY_FOR_CISO_DECISION", requires_ciso_approval: true}
            reason: "a"
          - id: "POL-002"
            enabled: true
            priority: 10
            match: {verification_status: "supported"}
            action: {decision: "REJECTED", requires_ciso_approval: false}
            reason: "b"
    """)
    with pytest.raises(PolicyConfigError):
        load_policy_config(path)


def test_invalid_risk_level_in_rule_rejected(tmp_path):
    path = _write_config(tmp_path, """
        policy_version: "1.0"
        rules:
          - id: "POL-001"
            enabled: true
            priority: 1
            match: {verification_status: "supported", risk_levels: ["EXTREME"]}
            action: {decision: "READY_FOR_CISO_DECISION", requires_ciso_approval: true}
            reason: "invalid risk level"
    """)
    with pytest.raises(PolicyConfigError):
        load_policy_config(path)


def test_missing_policy_config_file_fails_closed(tmp_path):
    missing = str(tmp_path / "does_not_exist.yaml")
    with pytest.raises(PolicyConfigError):
        load_policy_config(missing)
    result = _decide("supported", "LOW", config_path=missing)
    assert result["decision"] == "READY_FOR_CISO_INFORMATION"  # built-in default, no crash


def test_path_traversal_style_path_is_just_a_path_read_not_executed(tmp_path):
    """A '../../' style path is not special-cased: it is either a readable YAML
    file (validated like any other) or fails closed like any missing/invalid
    file. There is no code execution surface regardless (yaml.safe_load only)."""
    traversal_path = str(tmp_path / ".." / ".." / "definitely_missing_file.yaml")
    with pytest.raises(PolicyConfigError):
        load_policy_config(traversal_path)


# -- non-bypassable invariants (section 4.2), even with a hostile config ------

def test_config_cannot_turn_unsupported_into_information(tmp_path):
    path = _write_config(tmp_path, """
        policy_version: "1.0"
        rules:
          - id: "POL-200"
            enabled: true
            priority: 1000
            match: {verification_status: "unsupported"}
            action: {decision: "READY_FOR_CISO_INFORMATION", requires_ciso_approval: false}
            reason: "malicious attempt to silently close an unsupported claim"
    """)
    # The rule itself is schema-valid (READY_FOR_CISO_INFORMATION is a legal
    # `action.decision` value in general) -- the invariant is enforced at
    # decide()-time, not rejected at load time, precisely because this
    # combination (status=unsupported + that particular decision) is the
    # specific thing that must never happen regardless of what loads.
    result = _decide("unsupported", "LOW", config_path=path)
    assert result["decision"] == "REJECTED"  # built-in default wins, rule ignored
    assert result["applied_exception"] is False


def test_config_cannot_turn_contradicted_into_information(tmp_path):
    path = _write_config(tmp_path, """
        policy_version: "1.0"
        rules:
          - id: "POL-201"
            enabled: true
            priority: 1000
            match: {verification_status: "contradicted"}
            action: {decision: "READY_FOR_CISO_INFORMATION", requires_ciso_approval: false}
            reason: "malicious attempt to silently close a contradicted claim"
    """)
    result = _decide("contradicted", "CRITICAL", config_path=path)
    assert result["decision"] == "READY_FOR_CISO_DECISION"
    assert result["applied_exception"] is False


def test_insufficient_evidence_is_never_affected_by_any_configuration(tmp_path):
    """Even a config with a (schema-invalid, so rejected at load) attempt to
    match insufficient_evidence cannot reach decide()'s insufficient_evidence
    branch at all -- that branch never even calls into the config layer."""
    path = _write_config(tmp_path, """
        policy_version: "1.0"
        rules:
          - id: "POL-001"
            enabled: true
            priority: 100
            match: {verification_status: "supported", risk_levels: ["CRITICAL"]}
            action: {decision: "READY_FOR_CISO_DECISION", requires_ciso_approval: true}
            reason: "unrelated rule"
    """)
    result = _decide("insufficient_evidence", "CRITICAL", config_path=path)
    assert result["decision"] == "INSUFFICIENT_EVIDENCE"
    assert result["requires_ciso_approval"] is False
    assert result["applied_exception"] is False


def test_config_requires_ciso_approval_field_is_never_trusted_directly(tmp_path):
    """Even if a rule's action.requires_ciso_approval is False for a
    READY_FOR_CISO_DECISION outcome, decide() recomputes it purely from the
    final decision value -- defense in depth against a misconfigured rule."""
    path = _write_config(tmp_path, """
        policy_version: "1.0"
        rules:
          - id: "POL-300"
            enabled: true
            priority: 1000
            match: {verification_status: "supported", risk_levels: ["LOW"]}
            action: {decision: "READY_FOR_CISO_DECISION", requires_ciso_approval: false}
            reason: "misconfigured rule with an inconsistent approval flag"
    """)
    result = _decide("supported", "LOW", config_path=path)
    assert result["decision"] == "READY_FOR_CISO_DECISION"
    assert result["requires_ciso_approval"] is True  # recomputed, not trusted from YAML


def test_decide_never_mutates_verification_result_status_even_with_exceptions(tmp_path):
    path = str(DEFAULT_CONFIG_PATH)
    vr = _vr("contradicted")
    decide(
        verification_result=vr, mcp_score=_score("LOW"), decision_id="VAL-0001",
        session_id="SES-TEST0000", correlation_id="COR-TEST0000", policy_config_path=path,
    )
    assert vr["status"] == "contradicted"


def test_configuration_hash_is_stable_for_the_same_file():
    from mcp_server.policy_config import config_hash
    config = load_policy_config(DEFAULT_CONFIG_PATH)
    assert config_hash(config) == config_hash(config)


def test_configuration_hash_never_contains_a_filesystem_path():
    from mcp_server.policy_config import config_hash
    config = load_policy_config(DEFAULT_CONFIG_PATH)
    h = config_hash(config)
    assert "\\" not in h and "/" not in h and ":" not in h
