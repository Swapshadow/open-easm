# Open EASM V4.3

Open EASM V4.3 corrige les points remontés sur la V4.2.

## Nouveautés V4.3

- Sous-domaines publics améliorés :
  - `crt.sh` ;
  - HackerTarget Hostsearch ;
  - CertSpotter ;
  - fallback DNS sur noms courants.
- Inventaire IP moins bruyant :
  - classement des IP par périmètre ;
  - exposition principale ;
  - prestataires tiers ;
  - support ;
  - IP non publiques.
- Affichage IP priorisé :
  - les IP cœur sont affichées en premier ;
  - les IP de prestataires tiers sont résumées ;
  - les IP non publiques restent visibles.
- CTI / réputation moins verbeux :
  - résumé global ;
  - IP listées ou en erreur affichées en priorité ;
  - IP de prestataires tiers masquées du détail pour éviter le bruit.
- Sections déplacées plus haut :
  - constats priorisés ;
  - sous-domaines publics ;
  - inventaire IP.
- Logo remis à l’échelle.
- Fond rouge premium ajusté.
- Toutes les fonctionnalités V4.2 sont conservées :
  - PostgreSQL ;
  - historique ;
  - suppression audits ;
  - vérification DNS TXT ;
  - rapports Excel/PDF/JSON.

## Installation

Arrêter la V4.2 :

```bash
cd ~/open-easm-v4.2
docker-compose down
```

Installer la V4.3 :

```bash
cd ~
unzip open-easm-v4.3.zip
cd open-easm-v4.3
docker-compose up -d --build
```

Ouvrir :

```text
http://localhost:8000
```

## Remise à zéro complète de la base

```bash
docker-compose down -v
docker-compose up -d --build
```

Attention : `down -v` supprime le volume PostgreSQL de la version.
