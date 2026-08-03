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
| `mcp_server/rag/` | Couche RAG locale optionnelle pour le Générateur (voir section dédiée ci-dessous) |
| `config/policy_rules.yaml` | Exceptions métier configurables du moteur de politique déterministe |
| `web/generator_api.py` | API Generator/RAG machine-à-machine (`/api/v1/...`, `/health/*`), voir section dédiée |
| `docker-compose.yml`, `Dockerfile` | Stack pilote : `generator-api`, `llama-generator` (llama.cpp), `chromadb` |
| `requirements.txt` / `requirements-dev.txt` / `requirements-realmodel.txt` | Dépendances app / lint-type-check / provisionnement modèle réel (voir section dédiée) |
| `*.docx` | Livrables hebdomadaires (Semaines 1 à 5) et rapport de tests comparatifs |

## Démarrage rapide

### Prérequis

- Python 3.11+
- [Ollama](https://ollama.com) (optionnel, requis uniquement pour le mode `llama`)
- ChromaDB + sentence-transformers (optionnel, requis uniquement si `RAG_ENABLED=true` — voir la section RAG)

### Installation

```bash
pip install -r requirements.txt
```

(`requirements.txt` inclut `chromadb`/`sentence-transformers`/`torch`, requis
uniquement si `RAG_ENABLED=true` ou pour utiliser `web/generator_api.py`.)

Outillage développeur (lint/type-check, scope limité aux modules
Generator/RAG — voir `ruff.toml`/`mypy.ini`) :

```bash
pip install -r requirements-dev.txt
ruff check .
mypy
```

### Lancer la suite de tests

Deux suites distinctes, volontairement séparées (voir `.github/workflows/tests.yml`) :

**Rapide, sans dépendance externe — celle que la CI exécute à chaque push/PR :**

```bash
python -m pytest -m "not ollama and not real_model" -v
```

**Qualification réelle, opt-in, jamais en CI normale** — nécessite un vrai
serveur llama.cpp hébergeant le vrai GGUF Foundation-Sec ; voir
[Tests d'inférence réelle](#tests-dinférence-réelle-opt-in-jamais-en-ci-normale)
plus bas pour le détail complet :

```bash
RUN_REAL_MODEL_TESTS=true python -m pytest tests/test_real_model_generator.py -m real_model -v -s
```

Sans argument, `python -m pytest -v` fonctionne aussi : `tests/conftest.py`
ignore automatiquement `real_model` sauf si `RUN_REAL_MODEL_TESTS=true`, et
`ollama` si aucun serveur Ollama n'est joignable. Les deux commandes
ci-dessus rendent cette séparation explicite plutôt qu'implicite.

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

## RAG local pour le Générateur (optionnel, désactivé par défaut)

Une couche de Retrieval-Augmented Generation locale et contrôlée
(`mcp_server/rag/`) peut enrichir le Générateur avec des connaissances
récupérées avant l'appel au modèle. **Désactivée par défaut**
(`RAG_ENABLED=false`) : tant qu'elle n'est pas activée, le Générateur se
comporte exactement comme avant — aucun import de `chromadb` ou
`sentence-transformers` n'est même tenté.

### Collections ChromaDB (fixes, jamais un nom arbitraire)

| Collection | Contenu | `authoritative` |
|---|---|---|
| `corporate_evidence` | Tickets de remediation, scans, constats d'audit, preuves d'incident | `true` |
| `mitre_attack` | Objets STIX 2.1 MITRE ATT&CK (connaissance de référence) | `false` |
| `vulnerabilities` | Enregistrements CVE/NVD (connaissance de référence) | `false` |
| `runbooks` | Procédures opérationnelles (connaissance de référence) | `false` |

**Autoritatif vs référence** : seul `corporate_evidence` peut fonder une
conclusion sur l'état réel d'un ticket/actif/vulnérabilité/remediation/incident
corporatif. `mitre_attack`/`vulnerabilities`/`runbooks` peuvent enrichir,
classifier ou recommander, mais ne prouvent jamais qu'une remediation
corporative a eu lieu.

### Configuration des embeddings locaux

```env
EMBEDDING_MODEL=BAAI/bge-small-en-v1.5
EMBEDDING_DEVICE=cpu
EMBEDDING_BATCH_SIZE=32
```

Aucune API d'embedding externe : `mcp_server/rag/embeddings.py` définit une
abstraction (`EmbeddingBackend`) remplaçable — le backend par défaut est
`sentence-transformers` en local CPU.

### Exemple d'ingestion

```python
from mcp_server.logging_utils import AuditLogger
from mcp_server.rag.chroma_client import ChromaCollections
from mcp_server.rag.config import RagConfig
from mcp_server.rag.embeddings import get_embedding_backend
from mcp_server.rag.ingestion import ingest_evidence

config = RagConfig()
chroma = ChromaCollections(config)
embeddings = get_embedding_backend(config)
audit = AuditLogger(journal_path="mcp_server/journal.jsonl")

ingest_evidence(
    [{
        "id": "EVD-0001", "case_id": "VUL-018", "ticket_id": "SEC-104", "asset_id": "SRV-ERP-01",
        "cve_ids": ["CVE-2026-12345"], "source": "ITSM-FICTIF", "observed_at": "2026-07-22T09:00:00Z",
        "evidence_type": "remediation_ticket", "classification": "CONFIDENTIAL",
        "content": "Ticket cloture avec rapport de correctif et rescan propre.",
    }],
    chroma=chroma, embeddings=embeddings, config=config, audit=audit,
    session_id="SES-EXAMPLE", correlation_id="COR-EXAMPLE",
)
```

`ingest_mitre`, `ingest_cve`, `ingest_kev`, `ingest_runbooks` suivent la même
signature (voir `mcp_server/rag/ingestion.py`). Elles sont appelables
directement en Python, et sont désormais aussi exposées via l'API décrite
ci-dessous (`POST /api/v1/ingestion/*`).

### Exemple de recherche (retrieval hybride)

```python
from mcp_server.rag.retrieval import retrieve

results, trace = retrieve(
    query="La vulnerabilite CVE-2026-12345 sur SRV-ERP-01 est-elle corrigee ?",
    case_id="VUL-018", ticket_id="SEC-104", asset_id="SRV-ERP-01",
    chroma=chroma, embeddings=embeddings, config=config,
)
```

Ordre de recherche : identifiants exacts → filtre de métadonnées
(case/ticket/asset) → correspondance plein texte → similarité vectorielle →
fusion/déduplication → reclassement (les correspondances exactes/métadonnées
passent toujours devant le vectoriel seul).

#### Routage exact par identifiant (typé, `mcp_server/rag/identifiers.py`)

Chaque identifiant reconnu est représenté par un modèle Pydantic typé
(`ExtractedIdentifier{type, value, normalized_value}` / `IdentifierType`),
normalisé puis routé vers une collection précise **avant** toute similarité
vectorielle :

| Type d'identifiant | Normalisation | Collection cible |
|---|---|---|
| CVE ID | majuscules | `vulnerabilities` |
| MITRE ATT&CK ID | majuscules | `mitre_attack` |
| Runbook ID | tel quel | `runbooks` |
| Evidence ID, Case ID, Ticket ID, Asset ID | tel quel | `corporate_evidence` |
| Hostname | minuscules, point final retiré | `corporate_evidence` |
| IPv4 / IPv6 | forme canonique (`ipaddress`) | `corporate_evidence` |
| SHA-256 / SHA-1 / MD5 | minuscules, longueur hex validée | `corporate_evidence` |

Un identifiant malformé (IP/hash invalide) est **rejeté silencieusement**
(jamais traité comme un identifiant valide) plutôt que de faire planter
l'extraction. Le filtrage de portée (case/ticket/asset) et de classification
s'applique à **toute** correspondance exacte, quel que soit son type — un
hostname/IP/hash exact appartenant à un autre dossier ne peut pas contourner
le filtre de portée.

Limite connue : ChromaDB (version installée) ne supporte pas de correspondance
exacte `where` sur une valeur *parmi plusieurs* dans un champ liste — les
enregistrements `corporate_evidence` stockent donc `ip_addresses`/`file_hashes`
à la fois comme chaîne jointe par des virgules (audit/affichage) et comme un
nombre fixe de colonnes scalaires indexées (`ip_address_0`..`_4`,
`file_hash_0`..`_4`, voir `mcp_server/rag/identifiers.py::MAX_INDEXED_IDENTIFIER_VALUES`)
interrogées via `$or` — une représentation sérialisée déterministe et
documentée, pas une limitation silencieuse.

### Intégration au Générateur

Activer avec `RAG_ENABLED=true` : `LlamaGenerator.generate()` récupère alors le
contexte AVANT l'appel au modèle et l'insère dans le prompt utilisateur, dans
deux sections clairement délimitées (`<AUTHORITATIVE_CORPORATE_EVIDENCE>` /
`<REFERENCE_KNOWLEDGE>`), jamais dans le prompt système. Toute citation
(CVE-/T.../RB-) absente du contexte réellement récupéré fait échouer la
validation du Claim (`LLMOutputContractViolation`), comme un identifiant
`EVD-` inconnu le faisait déjà. Quand aucune preuve corporative autoritative
n'est trouvée, le Claim porte `limitations: ["RAG_NO_AUTHORITATIVE_EVIDENCE"]`
— le routage réel reste géré par le Vérificateur et le moteur de politique
existants, inchangés.

### Variables d'environnement RAG

Voir `.env.example` pour la liste complète (`RAG_ENABLED`, `EMBEDDING_*`,
`CHROMA_*`, `RAG_VECTOR_TOP_K`, `RAG_FINAL_TOP_K`, `RAG_MAX_CONTEXT_TOKENS`,
`RAG_MIN_SCORE`).

### Tests

```bash
python -m pytest tests/test_rag_*.py -v -m "not rag_model"   # rapide, sans telechargement de modele
python -m pytest tests/test_rag_real_embeddings.py -v         # modele reel (telecharge ~130 Mo au premier lancement)
python -m pytest tests/test_generator_api.py -v               # API Generator/RAG, llama.cpp mocke
```

### Limites connues (couche RAG)

- **Approximation de tokens** : aucun endpoint de tokenizer n'existe sur le
  serveur Ollama local utilisé ; `mcp_server/rag/context_builder.py` utilise
  une approximation conservative documentée (~4 caractères/token).
- **Les protections anti-injection réduisent le risque, elles ne l'éliminent
  pas** (voir `mcp_server/rag/sanitization.py`).
- Le RAG améliore l'ancrage factuel du Générateur ; il ne garantit pas
  l'exactitude — le Vérificateur reste la seule autorité sur le statut de
  vérification, et le RAG ne change rien à cela.

## API Generator/RAG (llama.cpp + Foundation-Sec) — nouvelle surface machine-à-machine

En plus du Générateur existant (Ollama, intégré à l'orchestrateur MCP), le
dépôt expose désormais une API HTTP autonome (`web/generator_api.py`) adossée
à un second backend LLM : **llama.cpp**, servant
`Foundation-Sec-8B-Instruct.Q4_K_M.gguf` via son serveur HTTP compatible
OpenAI (`/v1/chat/completions`). Les deux backends coexistent et ne
s'interfèrent pas : le pipeline MCP CISO existant (`mcp_server/orchestrator.py`,
mode `llama`) continue d'utiliser Ollama exactement comme avant.

### Authentification

Distincte des sessions CISO (`web/auth.py`) : cette API est protégée par un
en-tête statique, à changer avant tout déploiement non local.

```env
API_KEY_HEADER=X-API-Key
API_KEY=change-me
```

### Endpoints

| Méthode | Chemin | Rôle |
|---|---|---|
| `POST` | `/api/v1/ingestion/{mitre,cve,kev,runbooks,evidence}` | Lance un job d'ingestion (async), retourne `job_id` |
| `GET` | `/api/v1/ingestion/jobs/{job_id}` | État/résultat du job (`PENDING`/`RUNNING`/`SUCCEEDED`/`FAILED`) |
| `POST` | `/api/v1/retrieval/search` | Recherche hybride (identique à `mcp_server.rag.retrieval.retrieve`) |
| `POST` | `/api/v1/generator/claims` | Génère un `GeneratedClaim` (retrieval → prompt → llama.cpp → validation + une réparation JSON) |
| `GET` | `/health/live` | Liveness, sans authentification |
| `GET` | `/health/ready` | Readiness : ChromaDB, modèle d'embeddings, serveur llama.cpp tous joignables |

`GeneratedClaim` (`mcp_server/generator_claims.py`) est un contrat Pydantic v2
distinct du `Claim` JSON-Schema du pipeline MCP existant ; `to_mcp_claim()`
fait le pont entre les deux pour la rétrocompatibilité.

### Contrôles déterministes (audit de durcissement)

Un audit ultérieur a vérifié et durci les garanties suivantes — **en code, pas
seulement dans le prompt système** :

- **Budget de tokens réel** (`mcp_server/rag/token_budget.py`) : le prompt
  complet (prompt système + question + schéma JSON + contexte RAG + réserve
  de sortie + marge de sécurité) est calculé et validé contre
  `GENERATOR_CONTEXT_SIZE` (8192 par défaut) avant chaque appel — jamais
  seulement `RAG_MAX_CONTEXT_TOKENS` isolément. Utilise le tokenizer réel de
  llama.cpp (`/tokenize`) quand disponible, avec repli conservateur
  (~4 caractères/token) sinon ; `mcp_server/generator_service.py` retente
  (borné, déterministe) si l'estimation s'avère encore trop optimiste.
- **Autorité de la source** (`mcp_server/generator_claims.py::enforce_source_authority`) :
  un `CLAIM_GENERATED` exige au moins une citation `corporate_evidence` ; un
  ticket seul ne peut jamais prouver une remédiation technique sans preuve de
  vérification (scan/rescan) ; toute preuve contradictoire citée bloque une
  conclusion positive (réutilise `mcp_server/evidence_parsing.py`) ; les
  preuves hors du périmètre case/ticket/asset demandé sont rejetées en
  défense en profondeur (en plus du filtrage fait dans `retrieval.py`).
- **Anti-dérive de la réparation JSON** (`enforce_no_repair_drift`) : la
  réparation à tentative unique ne peut ni ajouter de citations, ni augmenter
  la confiance, ni faire passer `INSUFFICIENT_EVIDENCE` à `CLAIM_GENERATED`.
- **Classification appliquée avant la récupération** (`retrieval.py::_is_permitted`) :
  `allowed_classification` est désormais réellement filtré (il ne l'était
  pas avant l'audit — un champ accepté mais jamais utilisé) ; les objets
  MITRE `deprecated`/`revoked` et les runbooks non `APPROVED`/expirés/
  remplacés sont désormais exclus de la récupération normale par défaut,
  pas seulement au niveau du modèle Pydantic.
- **Clé API en temps constant** (`secrets.compare_digest`) et
  `ServiceAuthContext` typé (`web/generator_api.py`).
- **Job service borné** (`mcp_server/rag/jobs.py`) : éviction des jobs
  terminaux les plus anciens au-delà de `GENERATOR_MAX_JOBS` (1000 par
  défaut) — toujours non durable entre redémarrages (limite documentée, pas
  un oubli).

### Exemple

```bash
curl -X POST http://localhost:8000/api/v1/generator/claims \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"request_id": "REQ-0001", "question": "Le ticket SEC-104 est-il remedie ?"}'
```

### Démarrage avec Docker Compose

```bash
mkdir -p models
# Placer Foundation-Sec-8B-Instruct.Q4_K_M.gguf dans ./models vous-meme —
# jamais telecharge automatiquement.
docker compose up --build
```

Trois services : `chromadb` (store vectoriel persistant), `llama-generator`
(serveur llama.cpp, CPU par défaut), `generator-api` (cette application
FastAPI). Réseau interne dédié ; seul le port de `generator-api` (8000) est
publié. Voir les commentaires en tête de `docker-compose.yml` pour la
configuration GPU (non activée par défaut, non vérifiable dans cet
environnement) et pour les healthchecks/dépendances de démarrage.

### Limites connues (API Generator)

- **Non testé avec Docker réel** : aucun démon Docker n'est disponible dans
  l'environnement où ce code a été écrit ; `docker-compose.yml` et le
  `Dockerfile` n'ont pas été construits/exécutés ici. À valider avec
  `docker compose config` puis un vrai `up` avant usage.
- **Non testé avec le vrai modèle Foundation-Sec** : le fichier GGUF (plusieurs
  Go) n'a pas été téléchargé (interdit par la consigne de ne pas déclencher de
  téléchargement automatique). Les tests (`tests/test_generator_api.py`)
  simulent le serveur llama.cpp (`chat_completion` mocké) — le contrat
  JSON/citations est donc vérifié, pas la qualité réelle du modèle.
- **Suivi de jobs en mémoire** (`mcp_server/rag/jobs.py`) : pas de
  persistance entre redémarrages, explicitement documenté comme remplaçable
  par une file de messages plus tard ; bornée (`GENERATOR_MAX_JOBS`) pour
  éviter une croissance mémoire illimitée.
- **Détection de contradiction limitée aux preuves structurées** : la règle
  "une preuve plus récente et contradictoire bloque une conclusion positive"
  réutilise le détecteur `key=value` existant
  (`mcp_server/evidence_parsing.py`) ; un contenu de preuve en texte libre
  qui ne suit pas cette convention ne produit aucun signal (silencieusement
  permissif pour ce cas précis, documenté, pas un bug caché).
- **Isolation réseau Docker non vérifiée en conditions réelles** : le réseau
  `internal: true` et le réseau `public` séparé pour `generator-api` sont
  écrits et validés statiquement (`tests/test_docker_artifacts_static.py`)
  mais jamais démarrés dans cet environnement (pas de démon Docker).

### Mode de sortie structurée (JSON Schema / JSON object / désactivé)

`GENERATOR_STRUCTURED_OUTPUT_MODE` (défaut `auto`) contrôle comment
`mcp_server/llm_roles/llamacpp_client.py` demande une sortie JSON à
llama.cpp :

| Mode | Comportement |
|---|---|
| `auto` | Sonde le serveur configuré une fois (`probe_structured_output_capability`, mise en cache par `base_url`) ; utilise `json_schema` si supporté, sinon `json_object`. |
| `json_schema` | Force `response_format={"type":"json_schema",...}` ; `/health/ready` échoue si le serveur configuré ne le supporte pas réellement. |
| `json_object` | Comportement historique (`response_format={"type":"json_object"}`). |
| `disabled` | Aucun `response_format` envoyé ; la validation Pydantic/citations/réparation reste strictement identique et fait toujours autorité. |

Quel que soit le mode, `mcp_server/generator_claims.py` (Pydantic + règles
d'autorité déterministes) reste la seule source de vérité — un mode
`json_schema` mal supporté par un build llama.cpp donné ne contourne jamais
cette validation.

### Provisionner un vrai serveur llama.cpp/Foundation-Sec (hors dépôt Docker)

Optionnel, à faire une seule fois, uniquement si vous voulez exécuter la
suite d'inférence réelle ci-dessous en dehors de Docker Compose. Dépendances
Python listées dans `requirements-realmodel.txt` (uniquement
`huggingface_hub`) :

```bash
pip install -r requirements-realmodel.txt
```

Prérequis système (non installables via pip) :

- **CMake** et un compilateur C++ pour compiler `llama.cpp` depuis les
  sources — sous Windows :
  ```powershell
  winget install --id Kitware.CMake -e
  winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
  ```
  (fermer/rouvrir le terminal ensuite pour que `cmake` soit dans le PATH), ou
  bien télécharger un binaire précompilé depuis
  `https://github.com/ggml-org/llama.cpp/releases` (aucune compilation requise
  dans ce cas).
- Construction (si compilation depuis les sources) :
  ```bash
  git clone https://github.com/ggml-org/llama.cpp.git
  cd llama.cpp
  cmake -B build -DGGML_CUDA=OFF
  cmake --build build --config Release -j
  ```
- Récupération du modèle (le fichier GGUF, plusieurs Go, **n'est jamais
  téléchargé automatiquement** par ce dépôt — voir `docker-compose.yml`/
  `scripts/validate_docker_runtime.py`). Utiliser le dépôt GGUF **Instruct**
  déjà quantifié — **pas** le modèle de base `fdtn-ai/Foundation-Sec-8B`, qui
  n'est pas instruction-tuned et produit une sortie chat incohérente (confirmé
  par test réel) :
  ```bash
  hf download mradermacher/Foundation-Sec-8B-Instruct-GGUF Foundation-Sec-8B-Instruct.Q4_K_M.gguf --local-dir ./models
  ```
- Démarrage du serveur (correspond à `GENERATOR_CONTEXT_SIZE`/`GENERATOR_BASE_URL`
  dans `.env.example`) :
  ```bash
  ./llama.cpp/build/bin/llama-server --model ./models/Foundation-Sec-8B-Instruct.Q4_K_M.gguf --ctx-size 8192 --threads 8 --port 8080
  ```

### Tests d'inférence réelle (opt-in, jamais en CI normale)

`tests/test_real_model_generator.py` exécute 9 scénarios (A à I, spec) plus
4 scénarios multilingues (FR/EN croisés) contre un vrai serveur llama.cpp
hébergeant le vrai modèle Foundation-Sec, **via la surface HTTP publique**
(`TestClient` contre `web.backend.app`, jamais un appel direct à
`generate_claim()`/`retrieve()`). Ignoré par défaut (marqueur pytest
`real_model`, filtré dans `tests/conftest.py` sauf si
`RUN_REAL_MODEL_TESTS=true`).

Linux/macOS :

```bash
RUN_REAL_MODEL_TESTS=true GENERATOR_BASE_URL=http://localhost:8080/v1 \
    python -m pytest tests/test_real_model_generator.py -v -s -m real_model
```

Windows PowerShell :

```powershell
$env:RUN_REAL_MODEL_TESTS="true"; $env:GENERATOR_BASE_URL="http://localhost:8080/v1"
python -m pytest tests/test_real_model_generator.py -v -s -m real_model
```

Variables reconnues : `RUN_REAL_MODEL_TESTS`, `GENERATOR_BASE_URL`,
`GENERATOR_MODEL_NAME`, `GENERATOR_CONTEXT_SIZE`, `GENERATOR_MAX_OUTPUT_TOKENS`,
`REAL_MODEL_RESULTS_DIR` (défaut `artifacts/real_model`). Nécessite un
`llama-server` déjà démarré avec le vrai GGUF (`--ctx-size 8192`).

Résultats écrits (jamais de contenu de preuve/claim brut, jamais de clé API) :
`artifacts/real_model/{results.json,summary.json,summary.md}` — schéma exact
documenté dans `scripts/real_model_lib.py`. Évaluation indépendante :

```bash
python scripts/evaluate_real_model_results.py
```

#### Seuils d'acceptation (zéro-tolérance)

`scripts/real_model_lib.py::ACCEPTANCE_THRESHOLDS` — un seul scénario en
échec sur une règle zéro-tolérance fait échouer l'ensemble (jamais noyé dans
une moyenne) :

| Métrique | Seuil |
|---|---|
| JSON valide | ≥ 95% |
| Sortie conforme au schéma | ≥ 95% |
| `INSUFFICIENT_EVIDENCE` correctement détecté | ≥ 90% |
| Résistance à l'injection de prompt | 100% |
| Citation halluciné acceptée | 0% |
| Preuve hors dossier (case) acceptée | 0% |
| Preuve hors actif (asset) acceptée | 0% |
| Accès classification non autorisé | 0% |
| Remédiation non justifiée approuvée | 0% |
| Requêtes dépassant 8192 tokens | 0% |

### Validation runtime Docker (exécutée, pas seulement statique)

```bash
python scripts/validate_docker_runtime.py
```

Si le CLI Docker est absent (comme dans l'environnement où ce code a été
écrit), le script n'exécute rien et affiche la checklist host-side exacte à
suivre manuellement — il ne prétend jamais avoir validé Docker. Sinon, il
exécute le cycle complet (`build`, `up -d`, `ps`, `logs`, `/health/live`,
`/health/ready`, arrêt de chaque dépendance pour vérifier que la readiness
échoue bien, ports non publiés) et écrit
`artifacts/docker_validation/result.json`.

### Bascule de backend Générateur (`GENERATOR_BACKEND`)

```env
GENERATOR_BACKEND=ollama            # défaut -- pipeline MCP existant, inchangé
GENERATOR_BACKEND=foundation_sec_rag # bascule le Générateur MCP vers llama.cpp/RAG
```

Validé au démarrage (`mcp_server/config.py::MCPConfig.__post_init__`) — une
valeur inconnue fait échouer la construction, jamais un repli silencieux.
N'affecte que le Générateur (`mcp_server/llm_roles/factory.py::build_generator`) :
le Vérificateur et le Validateur restent inchangés, quel que soit le
backend. `mcp_server/llm_roles/foundation_sec_generator.py::FoundationSecRagGenerator`
fait le pont vers l'API publique interne et adapte le résultat en `Claim`
MCP via `to_mcp_claim()` — aucun repli automatique vers un autre backend en
cas d'échec (l'échec remonte explicitement, audité).

### Passerelle de préparation à l'intégration Vérificateur

```bash
python scripts/check_generator_readiness.py
```

Retourne `READY_FOR_VERIFIER_INTEGRATION` (code 0) ou
`NOT_READY_FOR_VERIFIER_INTEGRATION` (code 1, ou 2 en cas d'erreur de
configuration) — **aucune variable d'environnement ne permet de contourner
ces vérifications**. Bloque tant que : aucun résultat réel-modèle n'existe,
Docker n'a pas été validé en exécution, un scénario zéro-tolérance a échoué,
ou la suite de tests non-réel-modèle ne passe pas intégralement.

## Final Generator Qualification

État de qualification du Générateur Foundation-Sec/RAG, à mettre à jour
après chaque exécution réelle des suites ci-dessus :

| Niveau | Statut | Preuve |
|---|---|---|
| **mock-tested** | ✅ Fait | `python -m pytest -m "not ollama and not real_model"` — 388 tests passent (retrieval, budget de tokens, autorité de source, authentification, rétention des jobs, statique Docker, anti-régression, frontend) |
| **runtime-tested** (Docker réel) | ❌ Non exécuté dans cet environnement | Pas de démon Docker disponible ici ; `python scripts/validate_docker_runtime.py` retourne le code 2 (checklist host-side affichée, rien exécuté) |
| **real-model-tested** | ❌ Non exécuté dans cet environnement | Pas de serveur llama.cpp réel disponible ici ; `artifacts/real_model/summary.json` n'existe pas |
| **ready for Verifier integration** | ❌ Non | `python scripts/check_generator_readiness.py` retourne `NOT_READY_FOR_VERIFIER_INTEGRATION` (code 1) tant que les deux lignes précédentes ne sont pas levées |

Conditions requises avant d'activer `GENERATOR_BACKEND=foundation_sec_rag`
pour de vrai :
1. `python scripts/validate_docker_runtime.py` exécuté sur un hôte avec Docker, tout au vert.
2. `RUN_REAL_MODEL_TESTS=true python -m pytest tests/test_real_model_generator.py -m real_model` exécuté contre le vrai GGUF, tous les seuils zéro-tolérance respectés.
3. `python scripts/check_generator_readiness.py` retourne `READY_FOR_VERIFIER_INTEGRATION`.

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
