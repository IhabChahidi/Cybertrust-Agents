# S3 — MCP Server Architecture (Mock Mode)

Semaine 3 livre le serveur MCP de bout en bout (`mcp_server/`), exécutable
aujourd'hui en mode **mock** (aucun accès Copilot Studio / LLM externe), et prêt
à basculer en mode **réel** dès que l'accès est accordé, sans changement à
l'orchestrateur, aux schémas ou aux tests.

## Arborescence

```
mcp_server/
  schemas.py          Contrats JSON — Evidence, Claim, VerificationResult, MCPScore, ValidationDecision
  errors.py            Codes d'evenement (EventCode) + exceptions MCPBlockedError / MCPTechnicalFailure
  config.py             MCPConfig : mode mock/real, whitelist d'endpoints, timeouts/retries
  logging_utils.py      AuditLogger — journal JSONL append-only, redaction des secrets (TC-19)
  evidence_parsing.py    Parsing structure de raw_data (cle=valeur) — jamais de recherche de sous-chaine
  diagnostics.py         Avertissements deterministes derives des Evidence (ne reecrit jamais le statut du Verificateur)
  policy.py              Moteur de politique deterministe du Validateur (statut -> decision, requires_ciso_approval)
  scoring.py            Moteur MCPScore deterministe (L5)
  orchestrator.py        MCPServer — automate d'etats (L4)
  llm_roles/
    base.py              Interfaces abstraites Generator / Verifier / Validator
    mock_generator.py     Generateur deterministe (mode pilote actuel)
    mock_verifier.py      Verificateur deterministe (mode pilote actuel)
    mock_validator.py     Validateur deterministe (mode pilote actuel) — delegue a policy.decide()
    llama_generator.py    Generateur LLM reel (Ollama)
    llama_verifier.py     Verificateur LLM reel (Ollama) — seule autorite sur VerificationResult.status
    policy_validator.py   PolicyValidator — moteur de politique deterministe (aucun LLM), utilise en mode "llama"
    llama_validator.py    Alias de compatibilite deprecie (LlamaValidator = PolicyValidator)
    real_stub.py           Points d'integration Copilot Studio / LLM externe (a completer)
    factory.py             Selection mock/llama/real via MCPConfig.llm_mode
tests/
  test_pipeline.py, test_negative.py, test_isolation.py, test_traceability.py,
  test_technical_failures.py, test_scoring.py, test_policy.py, test_evidence_parsing.py,
  test_llama_generator_validation.py, test_no_human_review.py, ...
```

## Pourquoi le mode mock d'abord

Le pilote n'a pas encore d'accès Copilot Studio ni de modèle externe. Plutôt que
d'attendre, l'orchestrateur (`orchestrator.py`) ne dépend que des interfaces
abstraites `Generator` / `Verifier` / `Validator` définies dans `llm_roles/base.py`.
`mock_generator.py`, `mock_verifier.py` et `mock_validator.py` implémentent ces
interfaces avec une logique déterministe et explicable (mots-clés de contradiction,
marqueurs `"...=absent"` pour l'incomplétude), directement sur le catalogue
Evidence de la Semaine 2 — sans jamais appeler de service externe.

Cela permet de construire et de tester **dès maintenant** :
- le routage complet du serveur MCP (états, blocages, journalisation) ;
- le moteur de scoring MCPScore, entièrement déterministe et indépendant des LLM ;
- toute la grille de tests négatifs (schéma, référence, sécurité) ;
- l'isolation structurelle entre rôles (signatures qui empêchent physiquement
  toute fuite de contexte entre Vérificateur et Validateur).

## Point de bascule vers le mode réel

Quand l'accès Copilot Studio / LLM externe est accordé :

1. Implémenter `RealGenerator`, `RealVerifier`, `RealValidator` dans
   `mcp_server/llm_roles/real_stub.py` (le fichier contient déjà la checklist :
   lecture des identifiants uniquement via variables d'environnement, respect de
   la whitelist d'endpoints, gestion des timeouts/retries, validation de schéma
   de chaque réponse LLM avant de la retourner).
2. Positionner `MCP_LLM_MODE=real` (variable d'environnement lue par
   `MCPConfig.llm_mode`, voir `config.py`).
3. Ne rien changer ailleurs : `orchestrator.py`, `scoring.py` et la suite de
   tests ne référencent que les interfaces abstraites, jamais les classes mock
   ou real directement (sélection faite uniquement par `llm_roles/factory.py`).
4. Les tests existants (`tests/test_pipeline.py`, etc.) restent valides tels
   quels contre le mode mock ; ajouter des tests d'intégration dédiés au mode
   réel une fois les vrais modèles branchés, sans supprimer les tests mock.

## Automate d'états (L4)

```
INIT -> VALIDATION_ENTREE -> SELECTION_EVIDENCE -> GENERATION_CLAIM
     -> VERIFICATION -> DIAGNOSTICS -> SCORING -> VALIDATION -> DECISION_CISO -> COMPLETED
```

Seules deux étapes font appel à un LLM : **GENERATION_CLAIM** (le Générateur) et
**VERIFICATION** (le Vérificateur). Toutes les autres étapes — y compris
**DIAGNOSTICS** (`mcp_server/diagnostics.py`) et **VALIDATION**
(`mcp_server/policy.py`) — sont entièrement déterministes. DIAGNOSTICS calcule
des avertissements consultatifs à partir du contenu des Evidence (champ marqué
« absent », contradiction entre Evidence) mais **ne réécrit jamais**
`VerificationResult.status` : le Vérificateur en reste l'unique auteur.

Toute violation bloquante (schéma, référence, injection, exfiltration, endpoint
non autorisé, version de schéma non supportée, violation de propriété du score,
risque HIGH/CRITICAL sans approbation CISO) fait transiter la session vers
`BLOCKED`. Toute erreur non malveillante d'un fournisseur LLM (timeout, réponse
vide, erreur 5xx) fait transiter vers `TECHNICAL_FAILURE` après un nombre
limité de tentatives (`MCPConfig.llm_max_retries`), sans jamais être journalisée
comme une attaque.

**`COMPLETED` ne signifie pas qu'une décision sensible a été automatisée.**
Cela signifie que le pipeline déterministe a produit un dossier conforme aux
schémas, relié à des preuves, scoré et routé pour le CISO.

### Gouvernance : le CISO est la seule autorité humaine de décision

Il n'existe **aucun rôle de « revue humaine » séparé** et **aucun statut
HUMAN_REVIEW** dans ce pipeline. Le CISO est la seule autorité humaine de
décision. Toute affaire nécessitant un arbitrage, une confirmation, une
attention particulière ou une décision sensible est acheminée directement vers
lui via `READY_FOR_CISO_DECISION`. Le champ `decision` de ValidationDecision
(qui sert aussi de valeur de `ciso_routing`) ne peut prendre que ces quatre
valeurs (`mcp_server/policy.py`) :

- `READY_FOR_CISO_DECISION` — décision CISO requise (risque HIGH/CRITICAL,
  contradiction, ou avertissement diagnostique serieux). `requires_ciso_approval`
  est alors toujours `true`.
- `READY_FOR_CISO_INFORMATION` — inclus dans la synthèse d'information du CISO,
  **sans que cela signifie une approbation** : aucune décision immédiate n'est
  requise. Réservé aux dossiers `supported` en risque LOW/MEDIUM sans
  avertissement sérieux.
- `REJECTED` — recommandation du pipeline (Claim non confirmé par les Evidence),
  **pas un rejet final du CISO**.
- `INSUFFICIENT_EVIDENCE` — preuves insuffisantes pour conclure ; le CISO peut
  demander des preuves complémentaires (`REQUEST_MORE_EVIDENCE`).

Aucune action de remédiation ou d'approbation n'est jamais automatique. La
décision finale du CISO (APPROVE / REJECT / REQUEST_MORE_EVIDENCE / DEFER, L5
section 8) est enregistrée séparément via `MCPServer.record_ciso_decision(...)`,
jamais automatiquement, et reste distincte de la recommandation du pipeline
ci-dessus.

## Isolation des rôles (TC-14)

Les signatures de `Verifier.verify` et `Validator.validate` (dans `base.py`)
n'acceptent aucun paramètre permettant de transmettre l'historique ou le
contexte d'un autre rôle :
- `Verifier.verify(claim, evidence, ...)` — jamais le prompt ou l'historique du
  Générateur.
- `Validator.validate(verification_result, mcp_score, ...)` — jamais le
  catalogue Evidence, le Claim, ni le contexte du Vérificateur.

Cette isolation est **structurelle** (imposée par la forme des interfaces),
pas seulement conventionnelle, y compris en cas de mutualisation d'un même
modèle externe entre les deux rôles.

## Ownership du score (TC-17)

Le MCPScore n'est jamais calculé ni modifié par un rôle LLM. L'orchestrateur
rejette explicitement (`SCORE_OWNERSHIP_VIOLATION`) toute sortie de Générateur
ou de Vérificateur contenant un champ `score` ou `mcp_score` — en plus de la
protection `additionalProperties: false` déjà imposée par les schémas Claim et
VerificationResult.

## Limites connues du mode mock

- `exposure` et `impact` (facteurs MCPScore) sont dérivés heuristiquement de la
  sévérité de l'Evidence, faute de champs dédiés dans le contrat Evidence
  actuel — documenté dans `scoring.py`. À réviser dès que des Evidence réelles
  porteront ces attributs.
- La détection de contradiction/incomplétude du Vérificateur mock est fondée
  sur des marqueurs de mots-clés (`"stillpresent"`, `"invalidated"`,
  `"absent"`, etc.), suffisante pour valider le routage MCP mais pas
  représentative de la qualité de raisonnement d'un LLM réel.

---

## Durcissement de l'architecture à deux couches (revue ultérieure)

Cette section documente l'état **actuel** du pipeline suite à la revue qui a
introduit les diagnostics complets, la politique configurable et le
durcissement du frontend. Les valeurs `HUMAN_REVIEW` / `APPROVED_FOR_CISO_REVIEW`
mentionnées plus haut dans ce document, ou dans `docs/s3_llama_test_results.md`,
sont **historiques** : elles ne sont plus jamais produites (voir
`tests/test_no_human_review.py`, qui échoue si l'un ou l'autre littéral
réapparaît comme valeur produite hors des fichiers de migration/tests
adversariaux explicitement exclus).

### Pipeline actuel

```
CISO request -> selection Evidence -> Generateur (LLM) -> Claim
             -> Verificateur (LLM) -> VerificationResult
             -> diagnostics deterministes -> MCPScore (deterministe)
             -> PolicyValidator (deterministe) -> ValidationDecision -> CISO
```

Seuls **deux** stades font appel a un LLM : le Generateur et le Verificateur.
Le Verificateur est la **seule autorite** sur `VerificationResult.status` :
aucun composant deterministe ne le reecrit jamais (voir
`mcp_server/llm_roles/llama_verifier.py`, qui n'a plus aucun garde-fou
deterministe overridant le verdict). Les diagnostics et la politique sont des
signaux et une decision **consultatifs/deterministes**, jamais generatifs.

### Regles de diagnostics completes (mcp_server/diagnostics.py)

| Code | Declencheur | Severite |
|---|---|---|
| `EXPLICIT_ABSENCE_MARKER_DETECTED` | un champ `field=absent` explicite dans raw_data | SERIEUSE |
| `POTENTIAL_INTER_EVIDENCE_CONFLICT` | deux Evidence de meme sujet (identifiant de correlation partage) avec valeurs contradictoires sur un champ connu | SERIEUSE |
| `VERIFIER_DIAGNOSTIC_DISAGREEMENT` | le statut du Verificateur ne correspond pas a ce que les faits structures suggerent seuls | SERIEUSE |
| `CONTRADICTION_REQUIRES_CISO_DECISION` | statut Verificateur == `contradicted` | SERIEUSE |
| `MISSING_EXPECTED_FIELD` | un champ attendu pour le type d'Evidence (`EXPECTED_FIELDS_BY_EVIDENCE_TYPE`) est totalement absent de raw_data | SERIEUSE |
| `AMBIGUOUS_EVIDENCE` | langage ambigu detecte (regles `DIAG-AMB-001` a `008`) ou cloture ("done"/"closed") sans champ de preuve | SERIEUSE |
| `LOW_EVIDENCE_COVERAGE` | une seule Evidence disponible | INFORMATIONNELLE |
| `STALE_EVIDENCE` | Evidence de plus de 90 jours | INFORMATIONNELLE |

`MISSING_EXPECTED_FIELD` et `AMBIGUOUS_EVIDENCE` sont toujours SERIEUSES des
qu'elles se declenchent (simplification documentee : la condition de
declenchement elle-meme encode deja "le champ est necessaire" / "l'ambiguite
affecte la conclusion", il n'y a pas de second jugement contextuel separe).
`SERIOUS_WARNINGS` (qui force l'escalade vers `READY_FOR_CISO_DECISION` pour un
verdict `supported`) est **derive** de `DIAGNOSTIC_SEVERITY`, jamais maintenu
independamment.

Chaque diagnostic existe sous deux formes : `diagnostic_warnings` (liste de
codes, champ historique conserve pour compatibilite) et `diagnostic_details`
(liste d'objets structures `{code, severity, evidence_ids, field, message,
rule_id}`, champ additif optionnel).

### Politique configurable (mcp_server/policy_config.py, config/policy_rules.yaml)

Des exceptions metier peuvent etre exprimees en YAML, valide par un schema
JSON strict avant tout usage (`yaml.safe_load` uniquement — aucune execution de
code). Invariants **non contournables**, appliques en code independamment du
contenu du fichier :

- `insufficient_evidence` ne peut jamais etre cible par une regle (exclu du
  schema meme) -> `INSUFFICIENT_EVIDENCE` toujours, le MCPScore ne compense
  jamais l'absence de preuve.
- `unsupported` / `contradicted` ne peuvent jamais devenir
  `READY_FOR_CISO_INFORMATION`, meme si une regle (chargee) le tente — verifie
  et ignore au moment de `decide()`, pas seulement a la validation du schema.
- `HUMAN_REVIEW` ne peut pas meme etre exprime : absent de l'enum
  `action.decision` du schema de configuration.
- `requires_ciso_approval` est toujours recalcule depuis la decision finale en
  code, jamais fait confiance depuis le YAML.
- Configuration malformee (YAML invalide, doublon d'id/priorite, valeur
  d'enum invalide) => `PolicyConfigError`, la table par defaut integree au code
  est utilisee, jamais un crash ni une application partielle.

Chaque `ValidationDecision` expose `policy_version`, `policy_rule`,
`policy_reason` (si une regle a matche), `applied_exception` (booleen), et
`configuration_hash` (hash de contenu, jamais un chemin de fichier).

### Cas d'usage metier couverts (Workstream D)

UC-01 (cloture de ticket), UC-02 (remediation de vulnerabilite), UC-03 (action
d'audit), UC-04 (action d'incident), UC-05 (action de comite), UC-06
(inventaire ouvert/en retard/partiel/non prouve) — voir
`tests/test_business_use_cases.py` pour le detail scenario par scenario et le
rapport de session pour la matrice de couverture complete.

### Libelles CISO requis (frontend)

`web/static/js/components/ResultsPanel.js` utilise exactement :
`READY_FOR_CISO_INFORMATION` = « Information disponible — aucune décision
demandée » ; `READY_FOR_CISO_DECISION` = « Décision du CISO requise » ;
`REJECTED` = « Demande rejetée » ; `INSUFFICIENT_EVIDENCE` = « Preuves
insuffisantes ». Aucun bouton d'action CISO n'apparait hors de
`READY_FOR_CISO_DECISION`. Tout contenu derive d'Evidence/Claim/raisonnement
est echappe avant insertion dans le DOM (`escapeHtml`).

### Categories de tests et instructions Ollama

Marqueurs pytest (`pytest.ini`) : `unit`, `integration`, `ollama`, `frontend`,
`security`, `regression`. La suite normale (`py -m pytest`) ne depend jamais
d'un serveur Ollama actif : `tests/test_ollama_integration.py` est ignore
automatiquement si `http://localhost:11434` n'est pas joignable
(`tests/conftest.py::pytest_collection_modifyitems`). Pour l'executer
explicitement : `py -m pytest tests/test_ollama_integration.py -m ollama -v`.
Les tests frontend s'executent via Node : `node tests/frontend/test_results_panel.mjs`.

### Limites connues (revue actuelle)

- `MISSING_EXPECTED_FIELD`/`AMBIGUOUS_EVIDENCE` : simplification de severite
  documentee ci-dessus (toujours SERIEUSE des declenchement, pas de second
  jugement "cela affecte-t-il vraiment la conclusion").
- `STALE_EVIDENCE` utilise `datetime.now()` directement (pas d'abstraction
  d'horloge injectable) — les tests evitent la dependance a l'horloge murale en
  utilisant des dates fixes tres anciennes, mais une vraie abstraction
  d'horloge serait necessaire pour des tests portant sur le seuil exact.
- Aucune detection dediee d'incoherence chronologique (date de cloture
  anterieure a la date de creation, etc.) n'est implementee — seul le
  chevauchement de dates est enregistre pour audit dans les contradictions,
  jamais utilise pour resoudre automatiquement un conflit.
- `tests/test_business_use_cases.py` exerce la logique deterministe
  (Verificateur mock -> diagnostics -> score -> politique) directement sur des
  Evidence synthetiques, pas le pipeline complet `MCPServer.process_request`
  (qui exige des fixtures sur disque sous `catalogue/valid/`) — voir le
  docstring de ce fichier pour la justification.
