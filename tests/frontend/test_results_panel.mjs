// Frontend hardening tests (Workstream C.3) for web/static/js/components/ResultsPanel.js.
//
// Smallest-appropriate-framework choice: this repo has no JS test runner, and the
// module under test has no DOM dependency beyond `container.innerHTML` — so a
// plain Node script using the built-in `assert` module and a one-property fake
// "container" object covers every required check without adding a new
// dependency (jsdom, jest, etc.) for four small render functions.
//
// Run with:  node tests/frontend/test_results_panel.mjs

import assert from "node:assert/strict";
import { renderResults } from "../../web/static/js/components/ResultsPanel.js";

let failures = 0;
let passed = 0;

function test(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`PASS  ${name}`);
  } catch (err) {
    failures += 1;
    console.log(`FAIL  ${name}\n      ${err.message}`);
  }
}

function fakeContainer() {
  return { innerHTML: "", querySelectorAll: () => [] };
}

function baseResult(overrides = {}) {
  return {
    session_id: "SES-TEST0000",
    correlation_id: "COR-TEST0000",
    ciso_routing: "READY_FOR_CISO_INFORMATION",
    claim: {
      id: "CLM-0001", statement: "Le ticket SEC-1452 est correctement remedie.",
      evidence_ids: ["EVD-0001"], confidence: 0.8,
    },
    verification_result: {
      status: "supported", reasoning_summary: "Coherent avec les Evidence fournies.",
      supporting_evidence: ["EVD-0001"], contradicting_evidence: [], missing_evidence: [],
    },
    mcp_score: {
      value: 42, risk_level: "MEDIUM", calculation_version: "1.0",
      factors: { severity: 10, exposure: 8, impact: 10, evidence_quality: 9, verification: 20, contradiction_penalty: 0 },
    },
    validation_decision: {
      id: "VAL-0001", decision: "READY_FOR_CISO_INFORMATION", justification: "j",
      requires_ciso_approval: false, policy_rule: "RULE_SUPPORTED_LOW_MEDIUM_INFORMATION",
      diagnostic_warnings: [],
    },
    ...overrides,
  };
}

// -- exact required labels, no legacy values ---------------------------------

test("READY_FOR_CISO_INFORMATION uses the exact required label", () => {
  const c = fakeContainer();
  renderResults(c, baseResult());
  assert.match(c.innerHTML, /Information disponible — aucune décision demandée/);
});

test("READY_FOR_CISO_DECISION uses the exact required label", () => {
  const c = fakeContainer();
  const result = baseResult({
    ciso_routing: "READY_FOR_CISO_DECISION",
    validation_decision: { id: "VAL-0001", decision: "READY_FOR_CISO_DECISION", justification: "j", requires_ciso_approval: true, diagnostic_warnings: [] },
  });
  renderResults(c, result);
  assert.match(c.innerHTML, /Décision du CISO requise/);
});

test("REJECTED uses the exact required label", () => {
  const c = fakeContainer();
  const result = baseResult({
    ciso_routing: "REJECTED",
    verification_result: { status: "unsupported", reasoning_summary: "r", supporting_evidence: [], contradicting_evidence: [], missing_evidence: [] },
    validation_decision: { id: "VAL-0001", decision: "REJECTED", justification: "j", requires_ciso_approval: false, diagnostic_warnings: [] },
  });
  renderResults(c, result);
  assert.match(c.innerHTML, /Demande rejetée/);
});

test("INSUFFICIENT_EVIDENCE uses the exact required label", () => {
  const c = fakeContainer();
  const result = baseResult({
    ciso_routing: "INSUFFICIENT_EVIDENCE",
    verification_result: { status: "insufficient_evidence", reasoning_summary: "r", supporting_evidence: [], contradicting_evidence: [], missing_evidence: ["EVD-0001: champ absent"] },
    validation_decision: { id: "VAL-0001", decision: "INSUFFICIENT_EVIDENCE", justification: "j", requires_ciso_approval: false, diagnostic_warnings: [] },
  });
  renderResults(c, result);
  assert.match(c.innerHTML, /Preuves insuffisantes/);
});

test("no legacy decision values ever appear in rendered output", () => {
  const c = fakeContainer();
  renderResults(c, baseResult());
  assert.doesNotMatch(c.innerHTML, /HUMAN_REVIEW/);
  assert.doesNotMatch(c.innerHTML, /APPROVED_FOR_CISO_REVIEW/);
});

test("forbidden words never appear for an informational result", () => {
  const c = fakeContainer();
  renderResults(c, baseResult());
  const forbidden = [/\bapproved\b/i, /\bvalidated\b/i, /human review/i, /\baccepted\b/i, /auto-approved/i, /closure confirmed/i];
  for (const pattern of forbidden) {
    assert.doesNotMatch(c.innerHTML, pattern, `forbidden pattern ${pattern} found`);
  }
});

// -- no approval button for informational results ----------------------------

test("no APPROVE button (or any CISO action button) appears for READY_FOR_CISO_INFORMATION", () => {
  const c = fakeContainer();
  renderResults(c, baseResult());
  assert.doesNotMatch(c.innerHTML, /data-decision="APPROVE"/);
  assert.doesNotMatch(c.innerHTML, /data-decision="REJECT"/);
  assert.doesNotMatch(c.innerHTML, /data-decision="REQUEST_MORE_EVIDENCE"/);
  assert.doesNotMatch(c.innerHTML, /data-decision="DEFER"/);
});

test("no CISO action buttons appear for REJECTED or INSUFFICIENT_EVIDENCE either", () => {
  for (const routing of ["REJECTED", "INSUFFICIENT_EVIDENCE"]) {
    const c = fakeContainer();
    const result = baseResult({
      ciso_routing: routing,
      validation_decision: { id: "VAL-0001", decision: routing, justification: "j", requires_ciso_approval: false, diagnostic_warnings: [] },
    });
    renderResults(c, result);
    assert.doesNotMatch(c.innerHTML, /data-decision="APPROVE"/, `APPROVE button leaked for ${routing}`);
  }
});

test("CISO action buttons DO appear for READY_FOR_CISO_DECISION (a decision is actually pending)", () => {
  const c = fakeContainer();
  const result = baseResult({
    ciso_routing: "READY_FOR_CISO_DECISION",
    validation_decision: { id: "VAL-0001", decision: "READY_FOR_CISO_DECISION", justification: "j", requires_ciso_approval: true, diagnostic_warnings: [] },
  });
  renderResults(c, result);
  assert.match(c.innerHTML, /data-decision="APPROVE"/);
  assert.match(c.innerHTML, /data-decision="REQUEST_MORE_EVIDENCE"/);
});

// -- diagnostics: serious vs informational, unknown codes --------------------

test("serious diagnostics render distinguishably from informational ones", () => {
  const c = fakeContainer();
  const result = baseResult({
    validation_decision: {
      id: "VAL-0001", decision: "READY_FOR_CISO_DECISION", justification: "j", requires_ciso_approval: true,
      diagnostic_warnings: ["EXPLICIT_ABSENCE_MARKER_DETECTED", "LOW_EVIDENCE_COVERAGE"],
    },
  });
  renderResults(c, result);
  assert.match(c.innerHTML, /Champ explicitement marque absent detecte/);
  assert.match(c.innerHTML, /Couverture de preuve limitee/);
  // Both render as plain list items -- neither is styled/labeled as a blocking
  // error class; the "diagnostics are advisory, not a second verdict" framing
  // is in the surrounding card copy, not a per-item error state.
  assert.doesNotMatch(c.innerHTML, /class="error"/);
});

test("informational-only warnings do not render as blocking errors", () => {
  const c = fakeContainer();
  const result = baseResult({
    validation_decision: {
      id: "VAL-0001", decision: "READY_FOR_CISO_INFORMATION", justification: "j", requires_ciso_approval: false,
      diagnostic_warnings: ["STALE_EVIDENCE"],
    },
  });
  renderResults(c, result);
  assert.match(c.innerHTML, /Evidence potentiellement perimee/);
  assert.doesNotMatch(c.innerHTML, /class="[^"]*error/);
});

test("unknown future diagnostic codes render safely (fallback to raw code, no crash)", () => {
  const c = fakeContainer();
  const result = baseResult({
    validation_decision: {
      id: "VAL-0001", decision: "READY_FOR_CISO_INFORMATION", justification: "j", requires_ciso_approval: false,
      diagnostic_warnings: ["SOME_FUTURE_CODE_NOT_YET_KNOWN"],
    },
  });
  assert.doesNotThrow(() => renderResults(c, result));
  assert.match(c.innerHTML, /SOME_FUTURE_CODE_NOT_YET_KNOWN/);
});

test("missing optional fields (diagnostic_warnings absent, policy_rule absent) do not crash rendering", () => {
  const c = fakeContainer();
  const result = baseResult({
    validation_decision: { id: "VAL-0001", decision: "READY_FOR_CISO_INFORMATION", justification: "j", requires_ciso_approval: false },
  });
  assert.doesNotThrow(() => renderResults(c, result));
  assert.match(c.innerHTML, /Aucun avertissement diagnostique/);
});

// -- XSS / untrusted content escaping -----------------------------------------

test("HTML/script content inside the Claim statement is escaped, not executed", () => {
  const c = fakeContainer();
  const result = baseResult({
    claim: { id: "CLM-0001", statement: '<script>alert(1)</script>', evidence_ids: ["EVD-0001"], confidence: 0.8 },
  });
  renderResults(c, result);
  assert.doesNotMatch(c.innerHTML, /<script>alert\(1\)<\/script>/);
  assert.match(c.innerHTML, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
});

test("HTML content inside Verifier reasoning_summary is escaped", () => {
  const c = fakeContainer();
  const result = baseResult({
    verification_result: {
      status: "supported", reasoning_summary: '<img src=x onerror=alert(1)>',
      supporting_evidence: ["EVD-0001"], contradicting_evidence: [], missing_evidence: [],
    },
  });
  renderResults(c, result);
  assert.doesNotMatch(c.innerHTML, /<img src=x onerror=alert\(1\)>/);
  assert.match(c.innerHTML, /&lt;img/);
});

test("HTML content inside the ValidationDecision justification is escaped", () => {
  const c = fakeContainer();
  const result = baseResult({
    validation_decision: {
      id: "VAL-0001", decision: "READY_FOR_CISO_INFORMATION",
      justification: '<b onmouseover=alert(1)>injected</b>', requires_ciso_approval: false, diagnostic_warnings: [],
    },
  });
  renderResults(c, result);
  assert.doesNotMatch(c.innerHTML, /<b onmouseover=alert\(1\)>/);
});

console.log(`\n${passed} passed, ${failures} failed`);
if (failures > 0) process.exit(1);
