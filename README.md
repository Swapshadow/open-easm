# OpenEASM Beta

OpenEASM Beta est une plateforme open source d’External Attack Surface Management permettant d’obtenir rapidement une première vision défensive de l’exposition Internet publique d’un domaine.

L’objectif est de répondre à une question simple :

> Quelle est notre exposition Internet visible depuis l’extérieur ?

OpenEASM réalise des contrôles publics non exploitants : DNS, SPF, DMARC, MX, TLS/SSL, headers HTTP, sous-domaines publics, IP publiques, services exposés, Nmap service/version/port, corrélation CVE non exploitante, scoring de risque, Graph Explorer et rapports PDF / Excel / JSON.

## Installation en 7 étapes

### 1. Installer les prérequis

Sur Debian, Ubuntu ou Kali :

```bash<img width="1912" height="948" alt="image" src="https://github.com/user-attachments/assets/7f205654-7ff6-4c0d-bdec-25a965efeadc" />

sudo apt update
sudo apt install git docker.io docker-compose -y
sudo systemctl enable --now docker
