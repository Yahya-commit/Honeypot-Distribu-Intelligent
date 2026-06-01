# Configuration Kibana — Dashboard attaques

## 1. Créer la Data View

1. Ouvrir http://localhost:5601
2. **Stack Management** → **Data Views** → **Create data view**
3. Name : `Honeypot Attacks`
4. Index pattern : `honeypot-attacks-*`
5. Timestamp field : `@timestamp` (ou `timestamp` selon les événements Cowrie)

## 2. Visualisations recommandées

| Visualisation | Type | Champ |
|---------------|------|-------|
| Attaques dans le temps | Lens / Histogram | `@timestamp` |
| Top IPs sources | Data table | `attacker_ip` ou `src_ip` |
| Événements Cowrie | Pie chart | `eventid` |
| Mots de passe testés | Data table | `password` |

## 3. Dashboard

1. **Dashboard** → **Create dashboard**
2. Ajouter les visualisations ci-dessus
3. Exporter : **Share** → **PDF report** (ou capture d’écran pour le rapport)

## 4. Requête KQL utile

```
honeypot: cowrie and eventid: cowrie.login.failed
```

```
tags: dionaea
```
