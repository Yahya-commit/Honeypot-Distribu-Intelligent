# Honeypot Distribué Intelligent

Infrastructure de honeypots (Cowrie + Dionaea) pour la collecte d’attaques réelles, la génération d’**IOC** (Indicators of Compromise) et la visualisation via **ELK** et un **Threat Dashboard**.

> **Avertissement** : projet académique — à exécuter **uniquement** dans un laboratoire isolé (VM, VLAN dédié). Ne pas exposer sur Internet sans contrôle réseau strict.

## Objectifs pédagogiques

- Threat intelligence
- Analyse d’attaques
- Collecte IOC
- Sécurité réseau

## Architecture

```
Internet / Labo → Honeypots → IOC Collector → Threat Dashboard
                      ↓
                 Logstash → Elasticsearch → Kibana
```

## Livrables

| Livrable | Emplacement |
|----------|-------------|
| Infrastructure honeypot | `docker-compose.yml` |
| Base IOC | Volume Docker `/data/ioc` → `iocs.json`, `iocs.csv` |
| Dashboard attaques | http://localhost:8080 + Kibana :5601 |
| Rapport analytique | `docs/RAPPORT_ANALYTIQUE.md` |

## Prérequis

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows 10/11)
- 8 Go RAM recommandés (Elasticsearch)
- OpenSSH client (tests Cowrie)

## Démarrage rapide

```powershell
cd "c:\Users\PC\Desktop\Gestion des intusions"
copy .env.example .env
.\scripts\start.ps1
```

Attendre 2–3 minutes, puis :

```powershell
.\scripts\simulate-attack.ps1
```

### Accès aux services

| Service | URL / Commande |
|---------|----------------|
| Cowrie SSH | `ssh -p 2222 root@127.0.0.1` |
| Threat Dashboard | http://localhost:8080 |
| Kibana | http://localhost:5601 |
| Elasticsearch | http://localhost:9200 (interne) |

Configuration Kibana : voir [docs/KIBANA_SETUP.md](docs/KIBANA_SETUP.md).

## Structure du projet

```
.
├── docker-compose.yml      # Orchestration complète
├── elk/                    # Logstash + Kibana
├── ioc-collector/          # Extraction IOC (Python)
├── threat-dashboard/       # Dashboard Flask
├── ioc/data/               # Exemple IOC statique
├── docs/                   # Rapport + guide Kibana
└── scripts/                # Démarrage, tests, export
```

## Export des IOC

```powershell
.\scripts\export-iocs.ps1
# Fichiers dans ./exports/
```

## Types d’IOC collectés

- `ipv4` — adresses sources
- `username` / `password` — brute-force
- `command` — commandes shell
- `url` — URLs dans les commandes
- `sha256` / `md5` — malware téléchargé
- `protocol_probe` — scans Dionaea

## Pousser sur GitHub (rendu professeur)

```powershell
cd "c:\Users\PC\Desktop\Gestion des intusions"
git init
git add .
git commit -m "Projet honeypot distribué : Cowrie, Dionaea, ELK, collecteur IOC"
```

Créer un dépôt vide sur https://github.com/new (sans README), puis :

```powershell
git branch -M main
git remote add origin https://github.com/VOTRE_USERNAME/honeypot-distribue.git
git push -u origin main
```

Remplacez `VOTRE_USERNAME` et le nom du dépôt. GitHub demandera vos identifiants ou un **Personal Access Token**.

## Rédaction du rapport

Compléter [docs/RAPPORT_ANALYTIQUE.md](docs/RAPPORT_ANALYTIQUE.md) après vos tests (tableaux, captures Kibana, lien vers le repo).

## Arrêt de l’infrastructure

```powershell
docker compose down
```

Pour supprimer les volumes : `docker compose down -v`

## Auteur

**Yahya** — yahyabenelhaim1@gmail.com — 2026

## Licence

MIT — usage éducatif uniquement.
