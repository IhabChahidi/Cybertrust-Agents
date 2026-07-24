# CyberTrust Agents

Pilote SecOps multi-LLM sécurisé destiné au CISO — un serveur MCP orchestrant
trois rôles LLM isolés (Générateur, Vérificateur, Validateur) pour qualifier,
vérifier et scorer des dossiers SecOps fictifs, avec la décision finale
toujours réservée au CISO.

## Principe

```
Evidence → Claim → VerificationResult → MCPScore → ValidationDecision → CISO
```

- **Quatre contrats de données** stricts (JSON Schema, `additionalProperties: false`) : Evidence, Claim, VerificationResult, ValidationDecision.
- **MCPScore** : calculé exclusivement par le serveur MCP, jamais par un LLM.
- **Isolation structurelle** entre rôles — le Vérificateur ne voit jamais le contexte du Générateur, le Validateur ne voit jamais l'Evidence ni le Claim.
- **Aucune action sensible automatisée** : le pipeline route vers le CISO, il ne décide jamais à sa place.
- **Trois modes d'exécution** : `mock` (heuristiques déterministes), `llama` (modèles locaux via Ollama), `real` (Copilot Studio / LLM externe — à implémenter).

## Structure du dépôt

| Dossier | Contenu |
|---|---|
| `mcp_server/` | Serveur MCP : schémas, orchestrateur, moteur de scoring, rôles LLM |
| `catalogue/` | Catalogue Evidence fictif (`valid/` conforme, `negative/` fixtures invalides) |
| `tools/` | `validate_evidence.py`, `generate_hash.py` |
| `tests/` | Suite pytest (47 tests) couvrant la grille TC-01 à TC-20 |
| `web/` | Backend FastAPI + tableau de bord HTML/JS (authentification dev incluse) |
| `docs/` | Rapports de conformité et d'architecture (Semaines 2-3) |
| `*.docx` | Livrables hebdomadaires (Semaines 1 à 5) et rapport de tests comparatifs |

## Démarrage rapide

### Prérequis

- Python 3.11+
- [Ollama](https://ollama.com) (optionnel, requis uniquement pour le mode `llama`)

### Installation

```bash
pip install fastapi uvicorn jsonschema python-dotenv requests pytest
```

### Lancer la suite de tests

```bash
python -m pytest -v
```

### Valider le catalogue Evidence

```bash
python tools/validate_evidence.py
```

### Lancer le tableau de bord

Créer un fichier `.env` à la racine (jamais commité) :

```
CISO_DEV_USERNAME=ciso
CISO_DEV_PASSWORD=<votre mot de passe>
DELEGATE_DEV_USERNAME=ciso.delegate
DELEGATE_DEV_PASSWORD=<votre mot de passe>
```

Puis démarrer le serveur :

```bash
python -m uvicorn web.backend:app --port 8000 --reload
```

Ouvrir `http://localhost:8000` (ou générer un certificat local et servir en
HTTPS — voir `docs/s3_mcp_architecture.md`).

## État du projet

Le pilote suit une feuille de route en 5 semaines. Les Semaines 1 à 4 sont
closes ; la Semaine 5 (calibration, guides, indicateurs de qualité, backlog
d'industrialisation) est livrée et **en attente de validation (recette) par
le CISO**. Détail complet dans les livrables `.docx` et dans
`docs/s3_llama_test_results.md` pour les résultats de tests avec des modèles
LLM réels.

## Sécurité — mode développement uniquement

L'authentification du tableau de bord (`web/auth.py`) est un mécanisme réel,
appliqué côté serveur (sessions HttpOnly, CSRF, PBKDF2, verrouillage
anti-brute-force) mais explicitement conçu pour le développement : comptes et
sessions en mémoire, sans base de données persistante. À remplacer par un
fournisseur d'identité réel avant toute mise en production.
