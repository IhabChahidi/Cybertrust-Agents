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
  scoring.py            Moteur MCPScore deterministe (L5)
  orchestrator.py        MCPServer — automate d'etats (L4)
  llm_roles/
    base.py              Interfaces abstraites Generator / Verifier / Validator
    mock_generator.py     Generateur deterministe (mode pilote actuel)
    mock_verifier.py      Verificateur deterministe (mode pilote actuel)
    mock_validator.py     Validateur deterministe (mode pilote actuel)
    real_stub.py           Points d'integration Copilot Studio / LLM externe (a completer)
    factory.py             Selection mock/real via MCPConfig.llm_mode
tests/
  test_pipeline.py, test_negative.py, test_isolation.py, test_traceability.py,
  test_technical_failures.py, test_scoring.py   28 tests pytest, mappes sur la grille L7
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
     -> VERIFICATION -> SCORING -> VALIDATION -> DECISION_CISO -> COMPLETED
```

Toute violation bloquante (schéma, référence, injection, exfiltration, endpoint
non autorisé, version de schéma non supportée, violation de propriété du score,
risque HIGH/CRITICAL sans approbation CISO) fait transiter la session vers
`BLOCKED`. Toute erreur non malveillante d'un fournisseur LLM (timeout, réponse
vide, erreur 5xx) fait transiter vers `TECHNICAL_FAILURE` après un nombre
limité de tentatives (`MCPConfig.llm_max_retries`), sans jamais être journalisée
comme une attaque.

**`COMPLETED` ne signifie pas qu'une décision sensible a été automatisée.**
Cela signifie que le pipeline déterministe a produit un dossier conforme aux
schémas, relié à des preuves, scoré et routé pour le CISO
(`ciso_routing` ∈ {`READY_FOR_CISO_DECISION`, `READY_FOR_CISO_INFORMATION`,
`CLOSED_REJECTED`, `CLOSED_INSUFFICIENT_EVIDENCE`}). La décision finale du CISO
(APPROVE / REJECT / REQUEST_MORE_EVIDENCE / DEFER, L5 section 8) est enregistrée
séparément via `MCPServer.record_ciso_decision(...)`, jamais automatiquement.

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
