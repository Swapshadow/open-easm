# OpenEASM Alpha

**OpenEASM Alpha** est un outil EASM public non intrusif permettant d’obtenir rapidement une première vision de l’exposition Internet d’un domaine.

Il réalise des contrôles publics de surface d’attaque, sans exploitation, sans bruteforce et sans scan agressif.

## Fonctionnalités principales

- Audit DNS public
- Messagerie : SPF, DMARC, MX
- Web : accessibilité HTTP/HTTPS et headers de sécurité
- TLS/SSL : certificat, expiration, score TLS
- Sous-domaines publics par sources passives
- Inventaire IP public
- Distinction exposition cœur / prestataires
- CTI léger via DNSBL
- CVE potentielles passives basées sur les informations publiques
- Score exécutif par piliers
- Score technique cohérent sur 1000
- Rapports PDF, Excel et JSON
- Diagnostic système
- Reporting Center
- Vérification de propriété de domaine par DNS TXT

## Usage responsable

OpenEASM Alpha est conçu pour un usage défensif et responsable.

L’utilisateur reste responsable du domaine audité et doit disposer d’un cadre autorisé pour réaliser l’audit.

Cette version publique ne réalise pas :

- scan de ports Nmap ;
- exploitation de vulnérabilités ;
- bruteforce ;
- tests destructifs ;
- recherche de fuites d’identifiants ;
- contournement d’authentification.

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
unzip open-easm-main.zip
cd open-easm-main
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
    services/       # moteurs d'audit et scoring
    reports/        # génération PDF / Excel / JSON
    static/         # interface web
docker-compose.yml
README.md
.env.example
```

## Scoring OpenEASM Alpha

OpenEASM Alpha utilise un scoring par piliers :

- DNS
- Messagerie
- Web
- TLS/SSL
- Surface exposée
- CTI / Réputation
- CVE passives

Le score exécutif est calculé sur 100.

Le score technique est cohérent avec ce score :

```text
Score technique /1000 = Score exécutif /100 × 10
```

Exemple :

```text
Score exécutif : 67 / 100
Score technique : 670 / 1000
```

## Limites de la version Alpha

Cette version est une base publique de démonstration et d’amélioration continue.

Certaines sources passives peuvent être temporairement indisponibles, par exemple `crt.sh`.

Les CVE passives doivent être considérées comme des indices de priorisation, pas comme une preuve définitive de vulnérabilité.

## Roadmap

- Amélioration du moteur de scoring
- Mode avancé réservé aux domaines vérifiés
- Intégrations optionnelles Shodan / VirusTotal
- Meilleure comparaison entre audits
- Documentation utilisateur plus complète
- Packaging de production

## Auteur

Projet développé par Jean-Baptiste Terrazzoni.

## Avertissement

OpenEASM Alpha doit être utilisé uniquement dans un cadre autorisé. Aucun usage offensif ou non autorisé n’est encouragé.
