# S3 — Test Report (Mock Mode)

Généré à partir de `python -m pytest -v`, exécuté contre le serveur MCP en mode
mock (`MCP_LLM_MODE=mock`, valeur par défaut) et le catalogue Evidence de la
Semaine 2.

## Résultat global

```
28 passed in 1.02s
```

## Couverture par cas de test (grille L7)

| Cas de test | Scénario | Fichier / test | Résultat |
|---|---|---|---|
| TC-01 | Pipeline complet nominal | `test_pipeline.py::test_tc01_full_pipeline_nominal` | PASS |
| TC-02 | Claim avec plusieurs Evidence valides | `test_pipeline.py::test_tc02_claim_with_multiple_evidence` | PASS |
| TC-03 | Evidence de criticité moyenne | `test_pipeline.py::test_tc03_medium_severity_routes_to_information` | PASS |
| TC-04 | JSON malformé / schéma incomplet | `test_negative.py::test_tc04_malformed_claim_blocks_with_schema_error` | PASS |
| TC-05 | Claim sans Evidence (`evidence_ids=[]`) | `test_negative.py::test_tc05_empty_evidence_ids_blocks` | PASS |
| TC-06 | Evidence inexistante (`EVD-9999`) | `test_negative.py::test_tc06_nonexistent_evidence_id_blocks` | PASS |
| TC-07 | Champ obligatoire absent (`integrity_hash`) | `test_negative.py::test_tc07_evidence_missing_required_field_rejected` | PASS |
| TC-08 | Evidence contradictoires | `test_negative.py::test_tc08_contradictory_evidence_yields_human_review` | PASS |
| TC-09 | Preuves insuffisantes | `test_negative.py::test_tc09_insufficient_evidence_flagged` | PASS |
| TC-10 | Injection de prompt directe | `test_negative.py::test_tc10_prompt_injection_blocked` | PASS |
| TC-11 | Tentative d'exfiltration | `test_negative.py::test_tc11_exfiltration_attempt_blocked` | PASS |
| TC-12 | Endpoint non autorisé | `test_negative.py::test_tc12_unauthorized_endpoint_blocked` | PASS |
| TC-13 | Traçabilité session nominale | `test_traceability.py::test_tc13_*` (2 tests) | PASS |
| TC-14 | Isolation Vérificateur / Validateur | `test_isolation.py::test_*` (3 tests) | PASS |
| TC-15 | Champ supplémentaire non autorisé | `test_negative.py::test_tc15_extra_field_rejected` | PASS |
| TC-16 | Version de schéma inconnue | `test_negative.py::test_tc16_unsupported_schema_version_blocked` | PASS |
| TC-17 | Score non produit par le MCP | `test_negative.py::test_tc17_score_ownership_violation_blocked` | PASS |
| TC-18 | Timeout du fournisseur LLM | `test_technical_failures.py::test_tc18_llm_timeout_yields_technical_failure_not_block` | PASS |
| TC-19 | Secret présent dans une entrée | `test_technical_failures.py::test_tc19_*`, `test_redact_masks_common_secret_shapes` | PASS |
| TC-20 | Dossier HIGH/CRITICAL → décision CISO | `test_pipeline.py::test_tc20_high_or_critical_routes_to_ciso_decision` | PASS |

`test_scoring.py` (4 tests) couvre en complément la reproductibilité, les
bornes [0, 100] et les seuils de classification du moteur MCPScore (L5),
au-delà des 20 cas de la grille manuelle.

## Critères de réussite S3

| Critère | Résultat attendu | Statut |
|---|---|---|
| Chaîne exécutable de bout en bout sur le jeu contrôlé | Evidence → Claim → VerificationResult → MCPScore → ValidationDecision sans saut d'état | ✅ (`test_tc01`) |
| 100 % des sorties validées par schéma | `additionalProperties: false` appliqué et testé sur les 4 contrats | ✅ (`test_tc04`, `test_tc15`) |
| Sorties reliées à des preuves | `evidence_ids` résolus contre le catalogue statique, référence invalide bloquée | ✅ (`test_tc06`) |
| Statut information / décision CISO | `ciso_routing` distingue LOW/MEDIUM (information) et HIGH/CRITICAL (décision) | ✅ (`test_tc03`, `test_tc20`) |
| Isolation Vérificateur / Validateur | Signatures structurellement incapables de transporter le contexte d'un autre rôle | ✅ (`test_isolation.py`) |
| Score exclusivement MCP | Toute tentative d'un rôle LLM d'ajouter un champ `score` est rejetée | ✅ (`test_tc17`) |
| Aucune action sensible automatisée | `COMPLETED` ne vaut pas décision CISO ; `record_ciso_decision` est un appel séparé et explicite | ✅ (voir `docs/s3_mcp_architecture.md`) |
| Secrets jamais en clair dans le journal | Redaction testée sur API key / bearer token / champ `token=` | ✅ (`test_tc19`, `test_redact_masks_common_secret_shapes`) |

**Semaine 3 (mode mock) : tous les critères de sortie testables sans accès
externe sont satisfaits.** Le mode réel (`RealGenerator` / `RealVerifier` /
`RealValidator`) reste à implémenter dans `mcp_server/llm_roles/real_stub.py`
dès que l'accès Copilot Studio / LLM externe est accordé — voir la checklist
dans ce fichier et dans `docs/s3_mcp_architecture.md`.
