# Rapport analytique — Honeypot Distribué Intelligent

**Auteur :** [Votre nom]  
**Formation :** [Intitulé du cours]  
**Date :** [JJ/MM/AAAA]  
**Dépôt GitHub :** [URL du repository]

---

## 1. Résumé exécutif

Ce projet met en place une infrastructure de honeypots distribués (Cowrie, Dionaea) couplée à une stack ELK et un collecteur IOC automatisé. L’objectif pédagogique est de comprendre la **threat intelligence**, l’**analyse d’attaques**, la **collecte d’IOC** et la **sécurité réseau** dans un environnement contrôlé.

## 2. Architecture

```
Internet / Réseau labo
        │
        ▼
┌───────────────────┐
│  Honeypots        │
│  • Cowrie (SSH)   │
│  • Dionaea (multi)│
└─────────┬─────────┘
          │ logs
          ▼
┌───────────────────┐     ┌──────────────────┐
│  Logstash → ES    │     │  IOC Collector   │
└─────────┬─────────┘     └────────┬─────────┘
          │                        │
          ▼                        ▼
     Kibana (:5601)          Threat Dashboard (:8080)
                              iocs.json / iocs.csv
```

## 3. Méthodologie

1. Déploiement via Docker Compose sur machine isolée (VM / labo).
2. Génération de trafic de test (`scripts/simulate-attack.ps1`).
3. Agrégation des logs JSON Cowrie et logs Dionaea.
4. Extraction IOC : IPv4, credentials, commandes, URLs, empreintes SHA-256.
5. Corrélation visuelle dans Kibana et dashboard Flask.

## 4. Résultats (à compléter après tests)

| Indicateur | Valeur observée |
|------------|-----------------|
| Nombre total d’IOC | |
| IPs attaquantes uniques | |
| Tentatives SSH échouées | |
| Commandes injectées | |
| Fichiers téléchargés (SHA-256) | |

### 4.1 Top 5 adresses IP sources

| Rang | IP | Nombre d’événements | Pays (optionnel) |
|------|-----|---------------------|------------------|
| 1 | | | |
| 2 | | | |

### 4.2 Credentials les plus testés

| Utilisateur | Mot de passe | Occurrences |
|-------------|--------------|-------------|
| | | |

### 4.3 Exemples de commandes malveillantes

```
[Coller extraits depuis Kibana ou iocs.csv]
```

## 5. Analyse des menaces

- **Brute-force SSH** : comportement typique de botnets scanner (port 22/2222).
- **Téléchargement de payloads** : URLs et hashes à partager avec une threat feed.
- **Probes multi-protocoles (Dionaea)** : reconnaissance SMB, MSSQL, MQTT, etc.

## 6. IOC produits

Les fichiers livrables se trouvent dans le volume Docker ou après export :

- `iocs.json` — base structurée
- `iocs.csv` — import SIEM / Excel
- `stats.json` — métriques agrégées

Format d’un IOC :

```json
{
  "type": "ipv4",
  "value": "203.0.113.50",
  "source": "cowrie",
  "first_seen": "2026-06-01T10:00:00+00:00",
  "context": { "eventid": "cowrie.login.failed" }
}
```

## 7. Recommandations défensives

1. Désactiver l’authentification par mot de passe SSH ; utiliser des clés.
2. Bloquer les IP sources identifiées au niveau pare-feu / WAF.
3. Surveiller les indicateurs (URLs, hashes) via threat intelligence.
4. Limiter l’exposition des services non nécessaires sur Internet.

## 8. Limites et éthique

- Infrastructure **uniquement en laboratoire isolé**.
- Ne pas déployer sur réseau de production sans autorisation écrite.
- Données collectées = données personnelles potentielles (IPs) → RGPD / charte établissement.

## 9. Conclusion

[Synthèse des apprentissages : honeypot, pipeline SIEM, valeur des IOC pour la détection proactive.]

## 10. Annexes

- Captures Kibana
- Extrait `docker compose ps`
- Lien repository GitHub
