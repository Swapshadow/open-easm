# OpenEASM V7.2 - Correctif Nmap SYN scan

## Problème corrigé

La V7.1 forçait `-sT` pour être compatible Docker/WSL. Sur certaines cibles filtrées, cela peut ne rien retourner alors qu’un Nmap classique lancé en root utilise un SYN scan et détecte bien les ports ouverts.

## Nouveau comportement

OpenEASM V7.2 lance désormais :

```bash
nmap -sS -sV --version-all --reason -Pn --max-retries 2 --host-timeout 120s --open -oX - cible
```

- `-sS` : SYN scan, proche d’un Nmap classique root.
- `-sV --version-all` : détection service/version plus poussée, sans exploitation.
- `--reason` : permet de conserver la raison de détection côté Nmap.
- aucun script `exploit`, `brute`, `dos`, `intrusive`.
- fallback automatique en `-sT` uniquement si le conteneur n’a pas les droits raw socket.

## Docker

Le service backend ajoute :

```yaml
cap_add:
  - NET_RAW
```

Cela permet à Nmap d’utiliser le SYN scan dans le conteneur.

## Test conseillé

```bash
docker compose down
docker compose build --no-cache open-easm-api
docker compose up -d
docker exec -it openeasm-v7-api nmap -sS -sV --version-all --reason -Pn --open oehc.corsica
```
