# OpenEASM V7.5

**OpenEASM V7.5** est un outil EASM public défensif permettant d’obtenir rapidement une première vision de l’exposition Internet d’un domaine.

Il réalise des contrôles publics de surface d’attaque, avec une détection **service/version/port** et une corrélation CVE **non exploitante**.

## Fonctionnalités principales

- Avertissement juridique bloquant au lancement de l’application
- Case d’acceptation obligatoire avant tout audit
- Journalisation de l’acceptation : version du règlement, hash, date UTC, IP et user-agent
- Audit DNS public
- Messagerie : SPF, DMARC, MX
- Web : accessibilité HTTP/HTTPS et headers de sécurité
- TLS/SSL : certificat, expiration, score TLS
- Sous-domaines publics par sources passives
- Inventaire IP public
- Distinction exposition cœur / prestataires
- CTI léger via DNSBL
- CVE potentielles passives basées sur les informations publiques
- Nmap service/version/port limité : `-sV --version-light -Pn -T2 --max-retries 2 --host-timeout 60s --top-ports 100`
- Corrélation CVE locale depuis les versions détectées
- Barre de progression avec temps écoulé et temps restant estimé
- Score exécutif par piliers
- Score technique cohérent sur 1000
- Rapports PDF, Excel et JSON
- Diagnostic système, dont présence de Nmap
- Reporting Center
- Vérification de propriété de domaine par DNS TXT

## Usage responsable

OpenEASM V7.5 est conçu pour un usage défensif, autorisé et responsable.

L’utilisateur reste seul responsable des domaines, sous-domaines, adresses IP ou services qu’il soumet à l’analyse. Il doit disposer d’un droit, d’une autorisation explicite ou d’un motif légitime de sécurité informatique.

Cette version publique ne réalise pas :

- exploitation de vulnérabilités ;
- bruteforce ;
- attaque par déni de service ;
- scripts NSE `exploit`, `brute`, `dos` ou `intrusive` ;
- contournement d’authentification ;
- modification ou extraction frauduleuse de données.

Le scan Nmap V7.5 est volontairement limité à l’identification des ports ouverts, des services et des versions. La corrélation CVE est réalisée ensuite par OpenEASM à partir des informations de version.

## Prérequis

Installer :

- Docker
- Docker Compose
- Git

Sur Kali / Debian / Ubuntu :

```bash
sudo apt update
sudo apt install git docker.io docker-compose -y
sudo systemctl enable --now docker
```

Selon ton environnement, il peut être nécessaire d’ajouter ton utilisateur au groupe Docker :

```bash
sudo usermod -aG docker $USER
```

Puis fermer et rouvrir la session.

## Installation depuis GitHub

Cloner le projet :

```bash
git clone https://github.com/Swapshadow/open-easm.git
cd open-easm
```

Lancer OpenEASM :

```bash
docker-compose up -d --build
```

Ouvrir ensuite :

```text
http://localhost:8000
```

## Installation depuis une archive ZIP

Télécharger l’archive du projet depuis GitHub, puis :

```bash
unzip open-easm-v7.zip
cd open-easm-v7
docker-compose up -d --build
```

Ouvrir :

```text
http://localhost:8000
```

## Commandes utiles

Voir les conteneurs :

```bash
docker-compose ps
```

Voir les logs :

```bash
docker-compose logs -f open-easm-api
```

Arrêter l’application :

```bash
docker-compose down
```

Redémarrer :

```bash
docker-compose up -d --build
```

Réinitialiser complètement la base PostgreSQL :

```bash
docker-compose down -v
docker-compose up -d --build
```

Attention : `docker-compose down -v` supprime les données PostgreSQL et l’historique des audits.

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

## Scoring OpenEASM V7.5

OpenEASM V7.5 utilise un scoring par piliers :

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

## Limites de la version V7.5

Cette version reste une base publique de démonstration et d’amélioration continue.

Certaines sources passives peuvent être temporairement indisponibles, par exemple `crt.sh`.

Les CVE corrélées depuis les versions doivent être considérées comme des indices de priorisation. La présence exacte d’une vulnérabilité dépend de la distribution, des correctifs backportés, de la configuration et du contexte d’exposition.

## Roadmap

- Enrichissement de la base de corrélation CVE
- Mode avancé réservé aux domaines vérifiés
- Intégrations optionnelles Shodan / VirusTotal
- Meilleure comparaison entre audits
- Documentation utilisateur plus complète
- Packaging de production

## Auteur

Projet développé par Jean-Baptiste Terrazzoni.

## Avertissement

OpenEASM V7.5 doit être utilisé uniquement dans un cadre autorisé. Aucun usage offensif ou non autorisé n’est encouragé.


## Correctif V7.1 - Nmap Docker/WSL

La V7.1 force désormais Nmap en TCP connect scan avec `-sT`, utilise les 1000 ports TCP les plus fréquents et affiche le détail par cible. Cela rapproche le résultat d'un `nmap -sV -Pn --version-light --open domaine.tld` lancé depuis un terminal classique, tout en restant non exploitant.

Commande appliquée côté backend :

```bash
nmap -sT -sV --version-light -Pn -T2 --max-retries 2 --host-timeout 90s --top-ports 1000 --open -oX - cible
```

OpenEASM n'associe une CVE que lorsqu'une version suffisamment précise est détectée. Si Nmap affiche seulement `Apache httpd` sans numéro de version, le port est affiché mais aucune CVE n'est inventée.


## Nouveautés V7.5

- Correctif UX de l’acceptation juridique : le statut existant vérifie maintenant `accepted` côté backend et non plus uniquement `valid`.
- Ajout d’un délai de sécurité côté navigateur lors de l’enregistrement de l’acceptation, afin d’éviter un blocage silencieux sur “Enregistrement de l’acceptation…”.
- Rapport PDF retravaillé avec une mise en page plus professionnelle : couverture, KPI cards, synthèse direction, plan d’action priorisé, cartographie, Nmap et limites.
- Ajout d’un onglet **Graph Explorer** pour visualiser les relations entre domaine, sous-domaines, IP publiques, services exposés, CVE corrélées et constats.
- Ajout des endpoints `/api/audits/{audit_id}/graph` et `/api/graph/latest`.

Le Graph Explorer ne lance aucun scan supplémentaire : il visualise uniquement les données collectées par l’audit OpenEASM.

## Nouveautés V7.5

- Nouveau logo officiel `cyborg.png` intégré à l’application et aux icônes.
- Graph Explorer agrandi en grand format pour faciliter la visualisation des domaines, sous-domaines, IP publiques, services, CVE et constats.
- Conservation des garde-fous défensifs : aucune exploitation, aucun bruteforce, aucun DoS.
