# OpenEASM V7 — Notes de version

## Ajouts principaux

- Écran juridique bloquant au lancement de l’application.
- Case d’acceptation obligatoire avant tout accès aux audits.
- Vérification backend du jeton d’acceptation avant `/api/audit`.
- Journalisation de l’acceptation : version du règlement, hash SHA-256, date UTC, IP et user-agent.
- Détection Nmap limitée à service/version/port : `-sV --version-light -Pn -T2 --max-retries 2 --host-timeout 60s --top-ports 100`.
- Aucune exécution de scripts NSE `exploit`, `brute`, `dos` ou `intrusive`.
- Corrélation CVE locale depuis les versions détectées.
- Affichage d’une progression avec pourcentage, étape, temps écoulé et temps restant estimé.
- Section de résultats dédiée Nmap service/version/port.
- Exports PDF, Excel et JSON enrichis avec les résultats service/version/CVE.
- Diagnostic système enrichi avec le contrôle de présence de Nmap.
- Dockerfile backend mis à jour pour installer `nmap`.

## Positionnement sécurité

OpenEASM V7 reste un outil défensif. La détection CVE est une corrélation à partir d’informations de version accessibles par Nmap `-sV`. Elle ne confirme pas l’exploitabilité réelle d’une vulnérabilité.

## Fichiers importants

- `backend/app/services/legal_terms.py`
- `backend/app/services/nmap_audit.py`
- `backend/app/main.py`
- `backend/app/static/index.html`
- `backend/app/static/app.js`
- `backend/app/static/styles.css`
- `backend/Dockerfile`
- `backend/app/reports/pdf_report.py`
- `backend/app/reports/excel_report.py`
- `backend/app/reports/json_report.py`
