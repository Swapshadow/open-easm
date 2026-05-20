# OpenEASM V7.1 - Correctif Nmap Docker/WSL

## Problème corrigé

La première V7 lançait Nmap avec une commande volontairement très limitée :

```bash
nmap -sV --version-light -Pn -T2 --max-retries 2 --host-timeout 60s --top-ports 100 -oX - cible
```

Dans un conteneur Docker, Nmap peut se comporter différemment d'un lancement local classique. Exécuté en root dans le conteneur, il peut privilégier un scan SYN bas niveau. Selon le contexte Docker/WSL, cela peut produire des timeouts ou des résultats vides alors que le même test fonctionne depuis le terminal hôte.

De plus, `--top-ports 100` était trop restrictif pour se rapprocher d'un nmap classique. Par exemple, le port 8010 observé sur `oehc.corsica` n'était pas forcément couvert.

## Correction appliquée

La commande utilisée par OpenEASM V7.1 devient :

```bash
nmap -sT -sV --version-light -Pn -T2 --max-retries 2 --host-timeout 90s --top-ports 1000 --open -oX - cible
```

Changements :

- ajout de `-sT` pour forcer un scan TCP connect, plus compatible avec Docker/WSL ;
- passage de `--top-ports 100` à `--top-ports 1000` pour se rapprocher d'un nmap classique ;
- ajout de `--open` pour ne traiter que les ports ouverts ;
- augmentation du timeout cible à 90 secondes ;
- ajout d'un affichage détaillé par cible dans l'interface : statut, commande, durée et nombre de ports ouverts.

## Important

OpenEASM corrèle les CVE uniquement lorsqu'une version exploitable est détectée par Nmap.

Exemple :

```text
80/tcp open http Apache httpd
```

Dans ce cas, le produit est détecté, mais pas la version exacte. OpenEASM peut afficher le port et le service, mais ne doit pas inventer de CVE. Pour corréler une CVE, il faut une version du type :

```text
Apache httpd 2.4.49
```

## Variables configurables

Dans `docker-compose.yml` :

```yaml
OPENEASM_NMAP_TOP_PORTS=1000
OPENEASM_NMAP_HOST_TIMEOUT=90s
OPENEASM_NMAP_PROCESS_TIMEOUT=120
```
