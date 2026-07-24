# S2 — IAM Matrix (Minimal Service Account)

Conformément à la décision de gouvernance S1 (« IAM : Compte de service standard,
droits minimaux, environnement de développement isolé »), le pilote CyberTrust
Agents s'exécute avec un unique compte de service, sans accès à des données de
production ni à SharePoint réel.

## Spécification du compte de service

| Champ | Valeur |
|---|---|
| Nom | `svc-cybertrust-agents-dev` |
| Type | Compte de service standard (non interactif, non privilégié) |
| Environnement | Développement isolé uniquement — aucun accès à un environnement de staging ou de production |
| Authentification | HTTPS obligatoire, credentials stockés dans un coffre secret (jamais en clair, jamais commités) |
| Portée réseau | Endpoints whitelistés du serveur MCP uniquement (aucun appel sortant libre) |
| Durée de vie | Limitée au pilote (S1–S5) ; révocation à l'issue de la Semaine 5 |

## Droits accordés

| Ressource | Droit | Justification |
|---|---|---|
| `catalogue/valid/*.json`, `catalogue/negative/*.json` | Lecture seule | Le MCP doit pouvoir sélectionner des Evidence fictives pour la génération de Claims |
| Journal d'audit applicatif (dev) | Écriture append-only | Traçabilité des transitions, blocages et erreurs (session_id / correlation_id) |
| API du serveur MCP interne (endpoints whitelistés) | Appel (POST/GET restreints) | Orchestration validation → routage → scoring |
| Fournisseurs LLM externes (Vérificateur / Validateur), endpoints déclarés | Appel sortant restreint | Isolation des rôles ; aucun autre endpoint autorisé |

## Droits explicitement refusés

| Ressource | Refus | Justification |
|---|---|---|
| Données de production (tickets, scans, audits réels) | Aucun accès | Le pilote n'utilise que des Evidence entièrement fictives (note de cadrage S1) |
| SharePoint réel / tout connecteur documentaire réel | Aucun accès | Le nettoyage/dédup de documents réels est reporté à l'industrialisation |
| Secrets en clair dans le code ou les fichiers versionnés | Interdit | Toute fuite de secret dans le code ou les journaux est un incident (cf. TC-19) |
| Écriture sur le catalogue Evidence (`catalogue/valid/`, `catalogue/negative/`) | Refusé à l'exécution | Le catalogue est statique en S2–S5 ; seule `tools/generate_hash.py` le modifie hors exécution, en local |
| Accès direct à `VerificationResult`, `MCPScore`, `ValidationDecision` par le Générateur | Refusé | Isolation des contextes : le Générateur ne voit que les Evidence sélectionnées |
| Accès au contexte, aux prompts système ou à l'historique d'un autre rôle LLM (Vérificateur ↔ Validateur) | Refusé | Isolation stricte même en cas de mutualisation du modèle externe (TC-14) |
| Endpoints hors whitelist | Refusé (HTTP 403) | TC-12 — endpoint non autorisé |
| Actions sensibles / remédiation automatisée | Refusé | Le CISO reste l'unique autorité de décision |

## Principe

Droits minimaux, environnement isolé, aucune donnée réelle, aucun secret en dur,
aucune action automatique — le compte de service ne peut techniquement accéder
qu'aux ressources strictement nécessaires au traitement du catalogue statique
d'Evidence fictives.
