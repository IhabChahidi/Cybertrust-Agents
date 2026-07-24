# S2 — Evidence Mapping

Semaine 2 du pilote CyberTrust Agents. Catalogue statique de 10 Evidence fictives
(`catalogue/valid/`), toutes rattachées à la même session (`SES-20260722-PILOT`) et
à la même corrélation (`COR-20260722-PILOT`), couvrant les trois cas d'usage CISO
définis en Semaine 1 et les scénarios nominal / incomplet / contradictoire / non
conforme requis par le plan de tests (L7).

## Cas d'usage CISO

- **UC1 — Clôture des tickets de sécurité critiques**
- **UC2 — Remédiation des vulnérabilités prioritaires**
- **UC3 — Suivi des actions décidées lors des audits / incidents / comités de sécurité**

## Table de correspondance

| EVD ID | Cas d'usage | Scénario | Type | Cas de test couverts |
|---|---|---|---|---|
| EVD-0001 | UC1 | Ticket SEC-1452 marqué clôturé sans preuve de remédiation | ticket | TC-01, TC-02, TC-13 |
| EVD-0002 | UC1 | Validation record : aucune preuve de remédiation associée au ticket | validation_record | TC-01, TC-02, TC-08, TC-13 |
| EVD-0003 | UC1 | NOMINAL : ticket clôturé + rapport de correctif attaché (dossier complet) | validation_record | TC-01, TC-03 |
| EVD-0004 | UC2 | NOMINAL : scan post-correctif propre, CVE-2024-4711 | scan_result | TC-01, TC-02, TC-08 |
| EVD-0005 | UC2 | CONTRADICTOIRE : correctif déclaré mais vulnérabilité toujours présente (mêmes affected_assets/indicators qu'EVD-0004) | scan_result | TC-08 |
| EVD-0006 | UC2 | INCOMPLET : rapport de correctif sans résultat de nouveau scan | report | TC-09 |
| EVD-0007 | UC3 | NOMINAL : action clôturée, PV signé attaché | audit_record | TC-01, TC-03, TC-08 |
| EVD-0008 | UC3 | INCOMPLET : action ouverte, sans propriétaire ni échéance | audit_record | TC-09 |
| EVD-0009 | UC3 | CONTRADICTOIRE avec EVD-0007 : le PV est invalidé a posteriori (mêmes affected_assets/indicators qu'EVD-0007) | audit_record | TC-08 |
| EVD-0010 | UC2 | INSUFFISANT : rapport partiel, données clés manquantes | report | TC-09 |

## Paires contradictoires

Ces paires partagent volontairement les mêmes `affected_assets` et `indicators`
afin que le Vérificateur puisse les mettre en regard (`supporting_evidence` /
`contradicting_evidence`) :

- **EVD-0004 ↔ EVD-0005** — `SRV-WEB-07` / `CVE-2024-4711`
- **EVD-0007 ↔ EVD-0009** — `SRV-AUDIT-01` / `AUD-3390`, `PV-3390`

## Catalogue négatif

Les fichiers `catalogue/negative/EVD-N001.json` à `EVD-N003.json` ne représentent
aucun cas d'usage : ce sont des fixtures de non-conformité (TC-07, TC-10, TC-11,
TC-15). Voir `catalogue/negative/README.md` pour le détail.
