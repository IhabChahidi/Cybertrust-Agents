"""Centralized deterministic policy for the pipeline's final routing decision.

Governance constraint (this is the single source of truth for it): CyberTrust
Agents has exactly ONE human decision authority — the CISO. There is no separate
"human review" role and no HUMAN_REVIEW status anywhere in this pipeline. Every
case that needs arbitration, confirmation, additional attention, or a sensitive
decision is routed directly to the CISO via READY_FOR_CISO_DECISION. Nothing in
this module, or anywhere downstream of it, may reintroduce a routing value that
implies a reviewer other than the CISO.

Two deterministic layers make up the pipeline's non-generative decision-making:
  1. mcp_server.diagnostics — advisory signals derived from Evidence content,
     computed BEFORE this module runs. They never rewrite VerificationResult.status;
     the Verifier LLM remains its sole author, always.
  2. This module — the policy engine. It reads status, risk_level, and
     diagnostic_warnings, and computes the final ValidationDecision. It never
     calls an LLM, never recalculates MCPScore, and never edits
     VerificationResult.status.

Both MockValidator and PolicyValidator (mcp_server/llm_roles/policy_validator.py)
call decide() below, so mock mode and the real pipeline are guaranteed to apply
identical business rules.
"""

import functools
import logging
import warnings
from datetime import datetime, timezone

from mcp_server.diagnostics import SERIOUS_WARNINGS
from mcp_server.policy_config import DEFAULT_CONFIG_PATH, PolicyConfigError, config_hash, find_matching_rule, load_policy_config

_logger = logging.getLogger(__name__)

_VALID_STATUSES = {"supported", "unsupported", "contradicted", "insufficient_evidence"}
_VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_HIGH_RISK_LEVELS = ("HIGH", "CRITICAL")

# The only four decision values this pipeline may ever produce. There is no
# HUMAN_REVIEW and no APPROVED_FOR_CISO_REVIEW here: the CISO is the sole human
# decision authority, and every case needing their attention goes through
# READY_FOR_CISO_DECISION.
DECISION_READY_FOR_CISO_DECISION = "READY_FOR_CISO_DECISION"
DECISION_READY_FOR_CISO_INFORMATION = "READY_FOR_CISO_INFORMATION"
DECISION_REJECTED = "REJECTED"
DECISION_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

VALID_DECISIONS = frozenset({
    DECISION_READY_FOR_CISO_DECISION, DECISION_READY_FOR_CISO_INFORMATION,
    DECISION_REJECTED, DECISION_INSUFFICIENT_EVIDENCE,
})

# status -> (decision, policy_rule_id) for the three statuses whose routing does
# not depend on risk_level/diagnostics. "supported" is handled separately in
# _decide_status_routing because it is the one status where risk_level and
# diagnostic severity can change the outcome.
_FIXED_STATUS_TO_DECISION: dict[str, tuple[str, str]] = {
    "unsupported": (DECISION_REJECTED, "RULE_UNSUPPORTED_REJECTED"),
    "insufficient_evidence": (DECISION_INSUFFICIENT_EVIDENCE, "RULE_INSUFFICIENT_EVIDENCE"),
    # Never HUMAN_REVIEW. A contradiction is always an unresolved factual
    # conflict the CISO must see — the policy engine does not rewrite
    # VerificationResult.status="contradicted" to anything else, and does not
    # (by default) reject it either; see section 5 of the governance spec for
    # the documented-exception path this module does not implement.
    "contradicted": (DECISION_READY_FOR_CISO_DECISION, "RULE_CONTRADICTED_CISO_DECISION"),
}


class PolicyInputError(ValueError):
    """Raised when the policy engine is given a status/risk_level it does not
    recognize, or a VerificationResult/MCPScore missing a required field. Never
    silently coerced into a decision — fail closed. In the live pipeline this
    should be unreachable (JSON Schema already enforces both enums before
    _validation() runs), but decide() must not trust that as its only guarantee:
    it re-validates so it is also safe to call directly/in isolation (as the
    Validator truth-table tests do).
    """


# --- legacy decision-value migration (section 10) ---------------------------
#
# These aliases exist ONLY for reading historical data (e.g. an old journal
# entry) that predates the CISO-only routing model. The live pipeline never
# calls this function on its own output, and decide() below never produces
# these old values. The mapping is lossy for APPROVED_FOR_CISO_REVIEW: that
# value used to mean either "informational" or "needs a decision" depending on
# risk_level, which is no longer recoverable from the string alone, so the
# conservative (safer) target is chosen. Reprocess historical data against its
# original risk_level if exact fidelity matters.
_LEGACY_DECISION_ALIASES = {
    "APPROVED_FOR_CISO_REVIEW": DECISION_READY_FOR_CISO_DECISION,
    "HUMAN_REVIEW": DECISION_READY_FOR_CISO_DECISION,
}


def normalize_legacy_decision(value: str) -> str:
    """Translate a decision value from before the CISO-only routing redesign.
    Emits DeprecationWarning; raises PolicyInputError for anything unrecognized.
    Not used anywhere in the live pipeline's own output path.
    """
    if value in VALID_DECISIONS:
        return value
    if value in _LEGACY_DECISION_ALIASES:
        target = _LEGACY_DECISION_ALIASES[value]
        warnings.warn(
            f"Decision value {value!r} is deprecated and will not be produced by this "
            f"pipeline again; normalizing to {target!r} for reading historical data only.",
            DeprecationWarning, stacklevel=2,
        )
        return target
    raise PolicyInputError(f"unknown decision value: {value!r}")


def _decide_status_routing(status: str, risk_level: str, diagnostic_warnings: list[str]) -> tuple[str, str]:
    if status in _FIXED_STATUS_TO_DECISION:
        return _FIXED_STATUS_TO_DECISION[status]

    # status == "supported": the one case where risk_level and diagnostic
    # severity change the outcome.
    if risk_level in _HIGH_RISK_LEVELS:
        return DECISION_READY_FOR_CISO_DECISION, "RULE_SUPPORTED_HIGH_RISK_CISO_DECISION"
    if SERIOUS_WARNINGS.intersection(diagnostic_warnings):
        return DECISION_READY_FOR_CISO_DECISION, "RULE_SUPPORTED_DIAGNOSTIC_ESCALATION"
    return DECISION_READY_FOR_CISO_INFORMATION, "RULE_SUPPORTED_LOW_MEDIUM_INFORMATION"


# --- Workstream B: configuration-driven business exceptions ------------------
#
# Loaded once and cached; cleared via _reset_policy_config_cache() (tests only).
# A load/validation failure is logged and falls back to `None`, which means
# _apply_business_exception() below finds no config and always keeps the
# built-in default decision -- fail closed, never a crash, never a partially
# applied configuration.
@functools.lru_cache(maxsize=1)
def _cached_policy_config(path: str):
    try:
        config = load_policy_config(path)
    except PolicyConfigError as exc:
        _logger.warning("policy configuration rejected, using built-in default table: %s", exc)
        return None
    return config


def _reset_policy_config_cache() -> None:
    """Test-only hook: clear the cached config so tests can point at a different
    file or verify fail-closed behavior without process restart."""
    _cached_policy_config.cache_clear()


def _apply_business_exception(status: str, risk_level: str, default_decision: str, default_rule_id: str,
                               config_path: str) -> tuple[str, str, bool, str | None, str | None, str | None]:
    """Returns (decision, policy_rule, applied_exception, policy_version,
    policy_reason, configuration_hash). Falls back to the built-in default
    whenever: no config is loadable, no rule matches, or a matching rule's
    decision would violate a hard invariant (unsupported/contradicted ->
    READY_FOR_CISO_INFORMATION). insufficient_evidence is never passed here at
    all -- see decide(), which applies its fixed mapping before this is called.
    """
    config = _cached_policy_config(config_path)
    if config is None:
        return default_decision, default_rule_id, False, None, None, None

    rule = find_matching_rule(config, status=status, risk_level=risk_level)
    if rule is None:
        return default_decision, default_rule_id, False, config.get("policy_version"), None, config_hash(config)

    decision = rule["action"]["decision"]
    # Hard invariant, enforced here regardless of what the YAML says: no
    # configured rule may ever turn unsupported/contradicted into an
    # informational close.
    if status in ("unsupported", "contradicted") and decision == DECISION_READY_FOR_CISO_INFORMATION:
        _logger.warning(
            "policy rule %s attempted to route status=%r to READY_FOR_CISO_INFORMATION; "
            "ignoring and using the built-in default instead", rule["id"], status,
        )
        return default_decision, default_rule_id, False, config.get("policy_version"), None, config_hash(config)

    return decision, rule["id"], True, config.get("policy_version"), rule["reason"], config_hash(config)


def requires_ciso_approval(decision: str) -> bool:
    """READY_FOR_CISO_DECISION always requires explicit CISO sign-off before the
    dossier can be considered closed; nothing else does. This is a direct
    function of the decision value, not a separately-tracked flag that could
    drift out of sync with it."""
    return decision == DECISION_READY_FOR_CISO_DECISION


def _justification(status: str, decision: str, verification_result: dict, mcp_score: dict,
                    diagnostic_warnings: list[str]) -> str:
    warning_note = f" Avertissements diagnostiques : {', '.join(diagnostic_warnings)}." if diagnostic_warnings else ""

    if status == "unsupported":
        return (
            "Le Claim n'est confirme par aucune Evidence disponible. Ceci est une "
            f"recommandation du pipeline, pas un rejet final du CISO.{warning_note}"
        )
    if status == "insufficient_evidence":
        missing = "; ".join(verification_result.get("missing_evidence") or []) or "elements manquants non precises"
        return f"Preuves insuffisantes pour conclure : {missing}.{warning_note}"
    if status == "contradicted":
        return (
            "Evidence contradictoires detectees "
            f"({verification_result.get('reasoning_summary', '')}). Le statut 'contradicted' du "
            f"Verificateur est conserve tel quel ; le dossier est achemine au CISO, seule "
            f"autorite humaine de decision de ce pipeline.{warning_note}"
        )
    # supported
    base = (
        f"Claim supporte par les Evidence {verification_result.get('supporting_evidence', [])}, "
        f"score MCP {mcp_score.get('value')}/100 ({mcp_score.get('risk_level')})."
    )
    if decision == DECISION_READY_FOR_CISO_DECISION:
        base += " Achemine vers une decision CISO (risque eleve et/ou avertissement diagnostique serieux)."
    else:
        base += " Inclus dans la synthese d'information du CISO ; aucune decision immediate requise."
    return base + warning_note


def decide(*, verification_result: dict, mcp_score: dict, decision_id: str,
           session_id: str, correlation_id: str, diagnostic_warnings: list[str] | None = None,
           policy_config_path: str | None = None) -> dict:
    """The single, authoritative, deterministic policy function.

    Never calls an LLM, never recalculates MCPScore, never rewrites
    VerificationResult.status. Reads status, risk_level, and diagnostic_warnings
    (a list of string codes computed by mcp_server.diagnostics — never raw
    Evidence content) and applies the fixed routing rules above, then checks for
    a matching configured business exception (mcp_server/policy_config.py,
    config/policy_rules.yaml) that may narrow/redirect within the hard
    invariants. Fails closed (raises PolicyInputError) on any unrecognized enum
    value or missing identifier field, rather than guessing.
    """
    status = verification_result.get("status")
    if status not in _VALID_STATUSES:
        raise PolicyInputError(f"unknown or missing verification status: {status!r}")

    risk_level = mcp_score.get("risk_level")
    if risk_level not in _VALID_RISK_LEVELS:
        raise PolicyInputError(f"unknown or missing MCPScore risk_level: {risk_level!r}")

    if "id" not in verification_result:
        raise PolicyInputError("verification_result missing required field 'id'")
    if "id" not in mcp_score:
        raise PolicyInputError("mcp_score missing required field 'id'")

    diagnostic_warnings = list(diagnostic_warnings or [])
    decision, rule_id = _decide_status_routing(status, risk_level, diagnostic_warnings)

    applied_exception = False
    policy_version = None
    policy_reason = None
    configuration_hash = None
    # insufficient_evidence is NEVER passed to the configurable exception layer:
    # MCPScore/business rules must never compensate for missing Evidence, so
    # there is no path here by which configuration could change that outcome.
    if status != "insufficient_evidence":
        decision, rule_id, applied_exception, policy_version, policy_reason, configuration_hash = (
            _apply_business_exception(
                status, risk_level, decision, rule_id,
                str(policy_config_path or DEFAULT_CONFIG_PATH),
            )
        )

    result = {
        "schema_version": "1.0",
        "session_id": session_id,
        "correlation_id": correlation_id,
        "id": decision_id,
        "verification_result_id": verification_result["id"],
        "mcp_score_reference": mcp_score["id"],
        "decision": decision,
        "diagnostic_warnings": diagnostic_warnings,
        "justification": _justification(status, decision, verification_result, mcp_score, diagnostic_warnings)[:2000],
        "risk_level": risk_level,
        "requires_ciso_approval": requires_ciso_approval(decision),
        "policy_rule": rule_id,
        "applied_exception": applied_exception,
        "decided_at": datetime.now(timezone.utc).isoformat(),
        "validator_role": "VALIDATOR",
    }
    # policy_version / policy_reason / configuration_hash are optional in the
    # schema (may be entirely ABSENT, not merely null) -- e.g. no rule reason
    # applies when the built-in default table produced the decision. Omit the
    # key rather than set it to None: additionalProperties:False plus a
    # string-typed (non-nullable) schema property means `null` would fail
    # validation, while an absent optional key is always valid.
    if policy_version is not None:
        result["policy_version"] = policy_version
    if policy_reason is not None:
        result["policy_reason"] = policy_reason
    if configuration_hash is not None:
        result["configuration_hash"] = configuration_hash
    return result
