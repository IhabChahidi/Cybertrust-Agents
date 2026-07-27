"""Structured parsing of Evidence.content.raw_data (S1 convention: "key=value; key=value").

Business-logic signals derived from Evidence (missing-field detection, contradiction
detection) must never come from a naive substring search across the whole raw_data
blob. A naive `"absent" in raw_data.lower()` check, for example, fires just as
happily on a value like `patch_report=absent` as it does on a sentence such as
"le mot absent ne s'applique pas ici" or an attacker-supplied comment quoting
`status=absent` as an example. Every signal in this module is derived from exact,
parsed field VALUES instead — prose can never trigger a rule just by containing the
right word.
"""

import re
from itertools import combinations

_FIELD_PATTERN = re.compile(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.*?)\s*$")

# Fields that identify "the same real-world subject" across Evidence records. A
# contradiction is only meaningful when both records are about the same subject —
# two unrelated Evidence items that happen to share a status word are not a
# contradiction (e.g. one ticket's patch is "Clean" while an unrelated ticket's
# patch is "StillPresent": that is not a conflict about anything).
_CORRELATION_FIELDS = ("ticket_id", "cve_id", "action_id", "pv_reference")

# field name -> set of (baseline_value, anomaly_value) pairs that are a direct,
# factual contradiction when found on the SAME field for Evidence sharing a
# correlation field. Extend this table rather than adding new ad-hoc substring
# checks elsewhere.
_CONTRADICTORY_VALUE_PAIRS: dict[str, set[tuple[str, str]]] = {
    "result": {("clean", "vulnerabilitystillpresent")},
    "pv_status": {("signed", "invalidated")},
    # UC-01/UC-04/UC-05: one record says a ticket/action was closed, a later or
    # separate record says it was reopened/cancelled -- a direct factual
    # conflict about the same subject, regardless of which is more recent (see
    # find_contradictions' docstring: recency is recorded, never used to
    # silently resolve the conflict).
    "status": {("closed", "reopened"), ("completed", "cancelled")},
}


def parse_raw_data(raw_data: str) -> dict[str, str]:
    """Parse the "key=value; key=value" convention into a field dict.

    Segments that do not match `key=value` are ignored rather than raising —
    raw_data is free text by schema (EVIDENCE_SCHEMA), not every source is
    guaranteed to follow the convention, and an unparsable segment must never
    be treated as a rule match either way (fail closed on the side of "no
    signal found", not on the side of "guess something matched").
    """
    fields: dict[str, str] = {}
    for segment in (raw_data or "").split(";"):
        match = _FIELD_PATTERN.match(segment)
        if match:
            key, value = match.group(1).lower(), match.group(2).strip()
            if key and value:
                fields[key] = value
    return fields


def fields_marked_absent(evidence_item: dict) -> list[str]:
    """Field names whose PARSED VALUE is exactly "absent" (case-insensitive).

    Deliberately not a substring search: the word "absent" appearing inside a
    summary sentence, a quoted example, or an injected comment must never
    trigger this — only an actual `field=absent` key/value pair does, because
    only that is parsed as a field in the first place.
    """
    fields = parse_raw_data(evidence_item["content"]["raw_data"])
    return sorted(name for name, value in fields.items() if value.strip().lower() == "absent")


def _shared_subject(fields_a: dict, fields_b: dict) -> bool:
    return any(
        field in fields_a and field in fields_b
        and fields_a[field].strip().lower() == fields_b[field].strip().lower()
        for field in _CORRELATION_FIELDS
    )


def find_contradictions(evidence: list[dict]) -> list[dict]:
    """Pairwise-compare parsed fields across Evidence sharing a correlation
    identifier. Returns one record per exact contradictory-value-pair match:
    {field, baseline_id, baseline_value, anomaly_id, anomaly_value,
    date_baseline, date_anomaly}. Never a substring match, and never across
    Evidence about different subjects (see _shared_subject).

    Recency (the `date` field) is recorded for human context but never used to
    silently resolve the conflict — an unresolved factual conflict stays
    "contradicted" regardless of which side is chronologically newer, per the
    project's "no automated sensitive decision" principle: a human (the CISO)
    arbitrates contradictions, the pipeline never does.
    """
    parsed = [(e["id"], e.get("date", ""), parse_raw_data(e["content"]["raw_data"])) for e in evidence]
    hits: list[dict] = []
    for (id_a, date_a, fields_a), (id_b, date_b, fields_b) in combinations(parsed, 2):
        if not _shared_subject(fields_a, fields_b):
            continue
        for field_name, pairs in _CONTRADICTORY_VALUE_PAIRS.items():
            va = fields_a.get(field_name, "").strip().lower()
            vb = fields_b.get(field_name, "").strip().lower()
            if not va or not vb:
                continue
            for baseline_value, anomaly_value in pairs:
                if va == baseline_value and vb == anomaly_value:
                    hits.append({
                        "field": field_name,
                        "baseline_id": id_a, "baseline_value": va, "date_baseline": date_a,
                        "anomaly_id": id_b, "anomaly_value": vb, "date_anomaly": date_b,
                    })
                elif vb == baseline_value and va == anomaly_value:
                    hits.append({
                        "field": field_name,
                        "baseline_id": id_b, "baseline_value": vb, "date_baseline": date_b,
                        "anomaly_id": id_a, "anomaly_value": va, "date_anomaly": date_a,
                    })
    return hits
