# OpenEASM Beta

OpenEASM Beta est une plateforme open source d’External Attack Surface Management permettant d’obtenir rapidement une première vision défensive de l’exposition Internet publique d’un domaine.

L’objectif est de répondre à une question simple :

> Quelle est notre exposition Internet visible depuis l’extérieur ?

OpenEASM réalise des contrôles publics non exploitants : DNS, SPF, DMARC, MX, TLS/SSL, headers HTTP, sous-domaines publics, IP publiques, services exposés, Nmap service/version/port, corrélation CVE non exploitante, scoring de risque, Graph Explorer et rapports PDF / Excel / JSON.

---

## Sommaire

- [Fonctionnalités principales](#fonctionnalités-principales)
- [Usage responsable](#usage-responsable)
- [Installation en 7 étapes](#installation-en-7-étapes)
- [Commandes utiles](#commandes-utiles)
- [Installation depuis une archive ZIP](#installation-depuis-une-archive-zip)
- [Structure du projet](#structure-du-projet)
- [Nmap service/version/CVE](#nmap-serviceversioncve)
- [Graph Explorer](#graph-explorer)
- [Rapports](#rapports)
- [Scoring OpenEASM Beta](#scoring-openeasm-beta)
- [Limites](#limites)
- [Roadmap](#roadmap)
- [Auteur](#auteur)
- [Avertissement](#avertissement)

---

## Fonctionnalités principales

- Avertissement juridique bloquant au lancement de l’application
- Case d’acceptation obligatoire avant tout audit
- Journalisation de l’acceptation : version du règlement, hash, date UTC, IP et user-agent
- Audit DNS public
- Analyse messagerie : SPF, DMARC, MX
- Analyse Web : accessibilité HTTP/HTTPS et headers de sécurité
- Analyse TLS/SSL : certificat, expiration, version TLS, score TLS
- Découverte passive de sous-domaines publics
- Inventaire des IP publiques
- Distinction entre exposition principale, support et prestataires tiers
- CTI légère via DNSBL
- CVE potentielles passives basées sur les informations publiques
- Nmap service/version/port non exploitant
- Corrélation CVE locale depuis les versions détectées
- Barre de progression avec temps écoulé et temps restant estimé
- Score exécutif par piliers
- Score technique cohérent sur 1000
- Rapports PDF, Excel et JSON
- Diagnostic système, dont présence de Nmap
- Reporting Center
- Vérification de propriété de domaine par DNS TXT
- Graph Explorer relationnel

---

## Usage responsable

OpenEASM Beta est conçu pour un usage défensif, autorisé et responsable.

L’utilisateur reste seul responsable des domaines, sous-domaines, adresses IP ou services qu’il soumet à l’analyse.

Il doit disposer d’un droit, d’une autorisation explicite ou d’un motif légitime de sécurité informatique.

OpenEASM Beta ne réalise pas :

- exploitation de vulnérabilités ;
- bruteforce ;
- attaque par déni de service ;
- scripts NSE `exploit`, `brute`, `dos` ou `intrusive` ;
- contournement d’authentification ;
- modification de données ;
- extraction frauduleuse de données.

Le scan Nmap est limité à l’identification des ports ouverts, des services et des versions.  
La corrélation CVE est réalisée ensuite par OpenEASM à partir des informations de version visibles publiquement.

---

## Installation en 7 étapes

### 1. Mettre à jour Linux

Sur Debian, Ubuntu ou Kali :

```bash
sudo apt update
sudo apt upgrade -y
```

---

### 2. Installer Git

```bash
sudo apt install git -y
```

Vérifier l’installation :

```bash
git --version
```

---

### 3. Installer Docker

```bash
sudo apt install docker.io -y
sudo systemctl enable --now docker
```

Vérifier Docker :

```bash
docker --version
sudo systemctl status docker
```

---

### 4. Installer Docker Compose

Selon la distribution, deux méthodes sont possibles.

Méthode classique :

```bash
sudo apt install docker-compose -y
docker-compose --version
```

Méthode moderne avec le plugin Docker Compose :

```bash
sudo apt install docker-compose-plugin -y
docker compose version
```

OpenEASM fonctionne avec les deux syntaxes :

```bash
docker-compose up -d --build
```

ou :

```bash
docker compose up -d --build
```

---

### 5. Autoriser l’utilisateur à utiliser Docker

Optionnel mais recommandé :

```bash
sudo usermod -aG docker $USER
```

Fermer puis rouvrir la session Linux.

Vérifier ensuite :

```bash
docker ps
```

Si la commande fonctionne sans `sudo`, Docker est prêt.

---

### 6. Installer OpenEASM depuis GitHub

Cloner le projet :

```bash
git clone https://github.com/Swapshadow/open-easm.git
cd open-easm
```

Vérifier les fichiers :

```bash
ls
```

Tu dois voir notamment :

```text
backend/
docker-compose.yml
README.md
.env.example
```

---

### 7. Lancer OpenEASM Beta

Avec Docker Compose classique :

```bash
docker-compose up -d --build
```

Ou avec le plugin Docker Compose :

```bash
docker compose up -d --build
```

Vérifier les conteneurs :

```bash
docker-compose ps
```

ou :

```bash
docker compose ps
```

Ouvrir ensuite l’application dans un navigateur :

```text
http://localhost:8000
```

Au premier lancement, OpenEASM affiche un avertissement juridique obligatoire.  
L’application reste bloquée tant que l’utilisateur n’a pas accepté les conditions d’utilisation.

Vérifier l’API :

```bash
curl http://localhost:8000/api/health
```

Résultat attendu :

```json
{
  "status": "ok",
  "service": "openeasm-beta",
  "version": "beta-1.0"
}
```

---

## Commandes utiles

### Voir les conteneurs

```bash
docker-compose ps
```

ou :

```bash
docker compose ps
```

---

### Voir les logs de l’API

```bash
docker-compose logs -f open-easm-api
```

ou :

```bash
docker compose logs -f open-easm-api
```

---

### Arrêter OpenEASM

```bash
docker-compose down
```

ou :

```bash
docker compose down
```

---

### Redémarrer OpenEASM

```bash
docker-compose up -d --build
```

ou :

```bash
docker compose up -d --build
```

---

### Réinitialiser complètement la base PostgreSQL

```bash
docker-compose down -v
docker-compose up -d --build
```

ou :

```bash
docker compose down -v
docker compose up -d --build
```

Attention : `docker-compose down -v` supprime les données PostgreSQL et l’historique des audits.

---

## Installation depuis une archive ZIP

Télécharger l’archive du projet depuis GitHub, puis :

```bash
unzip open-easm-beta.zip
cd open-easm-beta
docker-compose up -d --build
```

ou :

```bash
unzip open-easm-beta.zip
cd open-easm-beta
docker compose up -d --build
```

Ouvrir ensuite :

```text
http://localhost:8000
```

---

## Structure du projet

```text
backend/
  app/
    services/       # moteurs d'audit, Nmap service/version, scoring
    reports/        # génération PDF / Excel / JSON
    static/         # interface web
  Dockerfile        # installe Nmap dans l'image backend

docker-compose.yml
README.md
.env.example
```

---

## Nmap service/version/CVE

OpenEASM Beta utilise Nmap pour identifier les ports ouverts, services et versions visibles publiquement.

La logique reste défensive :

```bash
nmap -sS -sV --version-all --reason -Pn --open
```

La corrélation CVE est ensuite réalisée côté OpenEASM, sans exploitation.

Exemples :

```text
Apache httpd 2.4.49 -> CVE-2021-41773 potentielle
Apache httpd 2.4.50 -> CVE-2021-42013 potentielle
```

Ces résultats sont des corrélations de version.  
Ils ne constituent pas une preuve d’exploitation.

Si une version n’est pas exposée, OpenEASM ne doit pas inventer de CVE.

Exemple :

```text
Apache httpd détecté
Version exacte : non exposée
CVE corrélable : non
```

---

## Graph Explorer

Le Graph Explorer permet de visualiser les relations entre :

- domaine racine ;
- sous-domaines ;
- IP publiques ;
- services exposés ;
- ports Nmap ;
- CVE corrélées ;
- constats de sécurité.

L’onglet Graph Explorer ne lance aucun scan supplémentaire.  
Il affiche uniquement les données collectées pendant l’audit OpenEASM.

---

## Rapports

OpenEASM Beta génère trois formats de rapport :

- PDF : rapport professionnel orienté direction et plan d’action ;
- Excel : classeur structuré avec onglets d’analyse ;
- JSON : export complet enrichi avec métadonnées.

Les rapports contiennent notamment :

- synthèse exécutive ;
- KPI ;
- score global ;
- score par pilier ;
- plan d’action priorisé ;
- constats localisés ;
- inventaire IP ;
- résultats Nmap ;
- corrélations CVE ;
- limites de l’audit ;
- politique non exploitante.

---

## Scoring OpenEASM Beta

OpenEASM Beta utilise un scoring par piliers :

- DNS
- Messagerie
- Web
- TLS/SSL
- Surface exposée
- CTI / Réputation
- CVE passives
- CVE service/version issues de la corrélation Nmap

Le score exécutif est calculé sur 100.

Le score technique est cohérent avec ce score :

```text
Score technique /1000 = Score exécutif /100 × 10
```

---

## Limites

OpenEASM Beta reste une base publique de démonstration et d’amélioration continue.

Certaines sources passives peuvent être temporairement indisponibles.

Les CVE corrélées depuis les versions doivent être considérées comme des indices de priorisation.

La présence exacte d’une vulnérabilité dépend :

- de la distribution utilisée ;
- des correctifs backportés ;
- de la configuration ;
- du contexte d’exposition ;
- de la présence ou non d’un reverse proxy ;
- de la fiabilité de la version exposée publiquement.

Une version masquée ne permet pas une corrélation CVE fiable.

Une version apparente peut être corrigée par backport de sécurité selon la distribution Linux utilisée.

---

## Roadmap

- Enrichissement de la base de corrélation CVE
- Mode avancé réservé aux domaines vérifiés
- Intégrations optionnelles Shodan / VirusTotal
- Amélioration des comparaisons entre audits
- Documentation utilisateur plus complète
- Packaging de production
- Amélioration continue des rapports
- Ajout de nouvelles sources passives

---

## Auteur

Projet imaginé par Jean-Baptiste Terrazzoni.

Développé avec l’assistance de GPT-5.5.

---

## Avertissement

OpenEASM Beta doit être utilisé uniquement dans un cadre autorisé.

Aucun usage offensif ou non autorisé n’est encouragé.

L’utilisateur est responsable de l’usage qu’il fait de l’outil et doit respecter les lois applicables.
