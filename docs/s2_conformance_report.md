# S2 — Conformance Report

Généré à partir de `python tools/validate_evidence.py`. Le script valide chaque
Evidence contre le schéma JSON défini en Semaine 1 (contrat Evidence, L3), vérifie
que `integrity_hash` correspond à `sha256(json.dumps(content, sort_keys=True))`, et
applique un contrôle minimal anti-injection de prompt sur `content.summary` /
`content.raw_data` (TC-10 / TC-11).

## Résultat — catalogue/valid (10/10 attendu PASS)

| ID | Schema | Hash | Résultat |
|---|---|---|---|
| EVD-0001 | PASS | PASS | **PASS** |
| EVD-0002 | PASS | PASS | **PASS** |
| EVD-0003 | PASS | PASS | **PASS** |
| EVD-0004 | PASS | PASS | **PASS** |
| EVD-0005 | PASS | PASS | **PASS** |
| EVD-0006 | PASS | PASS | **PASS** |
| EVD-0007 | PASS | PASS | **PASS** |
| EVD-0008 | PASS | PASS | **PASS** |
| EVD-0009 | PASS | PASS | **PASS** |
| EVD-0010 | PASS | PASS | **PASS** |

**10/10 valid Evidence files PASS.**

## Résultat — catalogue/negative (3/3 attendu FAIL)

| ID | Schema | Hash | Résultat | Défaut testé | Cas de test |
|---|---|---|---|---|---|
| EVD-N001 | FAIL | — | **FAIL (expected)** | `integrity_hash` absent | TC-07 |
| EVD-N002 | FAIL | — | **FAIL (expected)** | Champ non déclaré `extra_field` | TC-15 |
| EVD-N003 | PASS | FAIL | **FAIL (expected)** | Injection de prompt dans `content.raw_data` | TC-10, TC-11 |

**3/3 negative Evidence files correctly FAIL.**

Le fichier `EVD-N003` est délibérément conforme au schéma JSON (`id` respecte le
pattern, tous les champs requis sont présents) : sa non-conformité provient
uniquement du garde-fou anti-injection, ce qui isole ce cas de test des défauts de
schéma purs testés par EVD-N001 / EVD-N002.

## Sortie brute de la commande

```
$ python tools/validate_evidence.py
== catalogue/valid ==
ID          Schema    Hash      Result
----------------------------------------
EVD-0001    PASS      PASS      PASS
EVD-0002    PASS      PASS      PASS
EVD-0003    PASS      PASS      PASS
EVD-0004    PASS      PASS      PASS
EVD-0005    PASS      PASS      PASS
EVD-0006    PASS      PASS      PASS
EVD-0007    PASS      PASS      PASS
EVD-0008    PASS      PASS      PASS
EVD-0009    PASS      PASS      PASS
EVD-0010    PASS      PASS      PASS

10/10 valid Evidence files PASS

== catalogue/negative (expected to FAIL) ==
ID          Schema    Hash      Result
----------------------------------------
EVD-N001    FAIL      PASS      FAIL (expected)
    - <root>: 'integrity_hash' is a required property
    - id: 'EVD-N001' does not match '^EVD-[0-9]{4}$'
EVD-N002    FAIL      PASS      FAIL (expected)
    - <root>: Additional properties are not allowed ('extra_field' was unexpected)
    - id: 'EVD-N002' does not match '^EVD-[0-9]{4}$'
EVD-N003    PASS      FAIL      FAIL (expected)
    - prompt-injection pattern detected in content.raw_data: 'ignore (all )?previous instructions'

3/3 negative Evidence files correctly FAIL

Conformance check PASSED.
```

Exit code: `0`.

## S2 exit criteria

| Critère | Statut |
|---|---|
| `validate_evidence.py` exits 0 avec 10/10 PASS sur `catalogue/valid/` | ✅ |
| Toutes les Evidence de `valid/` partagent le même `session_id` (`SES-20260722-PILOT`) et `correlation_id` (`COR-20260722-PILOT`) | ✅ |
| Les paires contradictoires (EVD-0004/EVD-0005, EVD-0007/EVD-0009) partagent `affected_assets` et `indicators` | ✅ |
| `catalogue/negative/` contient exactement 3 fichiers, tous en échec de validation attendu | ✅ |
| `docs/` contient les 3 fichiers Markdown (`s2_evidence_mapping.md`, `s2_iam_matrix.md`, `s2_conformance_report.md`) | ✅ |

**Semaine 2 : critères de sortie tous satisfaits. Prêt pour la Semaine 3.**
