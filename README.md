# Security Platform

Plateforme backend légère d'analyse et de supervision de sécurité basée sur les
alertes Wazuh.

## Composants validés

Le backend couvre maintenant les briques suivantes :

- parser ;
- classifier ;
- déduplication ;
- corrélation ;
- risk score ;
- recommandations ;
- gestion des incidents ;
- API REST ;
- abstraction de source d'alertes.

Le pipeline métier reste séparé de la source des alertes :

```text
AlertSource
    ↓
raw Wazuh alerts
    ↓
Parser
    ↓
Classifier
    ↓
Deduplication
    ↓
Correlation
    ↓
Risk Score
    ↓
Recommendations
    ↓
Incidents
```

## AlertSource

Le module `backend/alert_source.py` introduit une abstraction explicite pour la
lecture des alertes brutes.

### `DemoAlertSource`

- source par défaut pour les tests et l'API locale ;
- fournit une alerte de démonstration basée sur le cas réel Wazuh `100101` ;
- ne dépend pas d'un environnement Wazuh actif.

### `WazuhAlertSource`

- lit un fichier Wazuh `alerts.json` ligne par ligne ;
- attend un chemin fourni explicitement, par exemple :
  `/var/ossec/logs/alerts/alerts.json` ;
- ignore proprement les lignes invalides ;
- retourne les alertes brutes au parser existant ;
- prévoit déjà un mode incrémental simple via un `offset` opaque.

Important :

- la source Wazuh ne modifie pas Wazuh, Docker, les permissions ni le fichier ;
- la connexion réelle à la VM Ubuntu sera validée séparément ;
- cette étape ne met pas encore en place de streaming temps réel complet.

## API REST

L'API FastAPI expose :

- `GET /health`
- `GET /alerts`
- `GET /alerts/{alert_id}`
- `GET /incidents`
- `GET /incidents/{incident_id}`
- `GET /statistics`

L'API n'embarque pas la logique d'analyse : elle appelle le pipeline backend
existant via une couche service.

## Configuration de la source

La source peut être choisie sans modifier le code.

### Mode démo

```bash
set ALERT_SOURCE_MODE=DEMO
python -m uvicorn backend.api:app --reload
```

### Mode Wazuh

Le backend est déployé dans son propre conteneur sur la VM Ubuntu. Il ne modifie
pas les conteneurs Wazuh : il lit uniquement le volume Docker existant
`single-node_wazuh_logs` monté en lecture seule sous `/wazuh-logs`.

```yaml
SECURITY_PLATFORM_ALERT_SOURCE: WAZUH
SECURITY_PLATFORM_WAZUH_ALERTS_PATH: /wazuh-logs/alerts/alerts.json
SECURITY_PLATFORM_MAX_ALERTS: "1000"
SECURITY_PLATFORM_REFRESH_BATCH_SIZE: "200"
```

Le fichier [docker-compose.backend.yml](docker-compose.backend.yml) contient
cette configuration et référence le volume externe sans toucher au stack Wazuh :

```bash
docker compose -f docker-compose.backend.yml up -d --build
```

La source lit en binaire avec un offset en octets. Chaque requête de consultation
déclenche un refresh borné : les nouvelles lignes sont ajoutées, une ligne JSON
finale incomplète est relue plus tard, et une troncature ou un remplacement du
fichier reprend au début du nouveau fichier. La fenêtre mémoire garde au plus
`SECURITY_PLATFORM_MAX_ALERTS` alertes récentes.

## Cas réel 100101

Le cas réel de référence reste couvert de bout en bout :

- `rule_id = 100101`
- catégorie `Privilege Escalation`
- sous-catégorie `Sudo / Group Modification`
- `risk_score = 78`
- sévérité `Critical`
- agent `compute2-endpoint`
- commande contenant `usermod -aG sudo wazuh-suspicious`

En mode démo, `GET /incidents` retourne un incident :
`Unauthorized sudo privilege modification`.

## Limitations actuelles

- pas encore de streaming temps réel ;
- pas encore de base de données ;
- pas encore de dashboard ni de frontend ;
- les incidents et leurs statuts restent en mémoire dans la fenêtre active.

## Structure

```text
security-platform/
├── backend/
│   ├── __init__.py
│   ├── alert_source.py
│   ├── api.py
│   ├── classifier.py
│   ├── correlation.py
│   ├── incidents.py
│   ├── models.py
│   ├── parser.py
│   ├── recommendations.py
│   └── risk_score.py
├── data/
│   └── sample_alert_100101.json
├── tests/
│   ├── test_alert_source.py
│   ├── test_api.py
│   ├── test_classifier.py
│   ├── test_correlation.py
│   ├── test_incidents.py
│   ├── test_parser.py
│   ├── test_recommendations.py
│   └── test_risk_score.py
├── README.md
├── Dockerfile
├── docker-compose.backend.yml
└── requirements.txt
```

## Tests

```bash
python -m unittest discover -s tests -v
```
