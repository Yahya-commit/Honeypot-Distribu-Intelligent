# Configuration Kibana — Dashboard attaques

## Méthode rapide (recommandée)

```powershell
cd "c:\Users\PC\Desktop\Gestion des intusions"
.\scripts\setup-kibana.ps1
```

Puis ouvrir directement : **http://localhost:5601/app/discover**

## 1. Créer la Data View (interface web)

1. Ouvrir http://localhost:5601
2. **Stack Management** → **Data Views** → **Create data view**
3. Name : `Honeypot Attacks`
4. Index pattern : `honeypot-attacks-*`
5. Timestamp field : **`@timestamp`** (obligatoire — pas laisser vide)

### Discover vide / « Fields 0 » / aucun résultat ?

**Cause la plus fréquente :** la plage de temps en haut à droite est trop courte (ex. *Last 15 minutes*) alors que vos logs datent d’hier ou d’une autre heure.

**Solution :**
1. En haut à droite, cliquez sur le **sélecteur de temps**
2. Choisissez **Last 30 days** ou **Absolute** → du 1er juin au jour actuel
3. Cliquez **Update**
4. Vérifiez que la vue est **Honeypot Attacks** (pas « security » ou autre)
5. Barre de recherche KQL : **vide** (supprimez tout filtre)
6. À gauche, cherchez et **ajoutez** ces champs (bouton +) : `eventid`, `src_ip`, `username`, `password`, `message`

**Script rapide :**
```powershell
.\scripts\open-discover.ps1
.\scripts\generer-logs.ps1   # si toujours vide
```

Le compteur de documents doit afficher **> 0** (ex. 35 hits).

### Erreur « Bad Request / undefined » ?

- **Ne pas recréer** la vue si elle existe déjà → aller directement dans **Discover**
- Vérifier que des logs existent : `docker exec hp-elasticsearch curl -s "http://localhost:9200/honeypot-attacks-*/_count"`
- Si le compteur est `0`, refaire des tests SSH : `ssh -p 2222 root@127.0.0.1`
- Utiliser le script : `.\scripts\setup-kibana.ps1`

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
