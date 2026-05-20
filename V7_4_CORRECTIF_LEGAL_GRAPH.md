# OpenEASM V7.5 — Correctif acceptation juridique et Graph Explorer

## Correctifs

- Correction de l'écran juridique : après acceptation backend, la fenêtre est fermée de manière forcée côté UI (`hidden`, `aria-hidden`, `display:none`) et l'utilisateur est renvoyé vers l'onglet Audit.
- Validation du jeton d'acceptation : le frontend vérifie maintenant explicitement que le backend retourne un token.
- Renforcement de la fonction `setTermsAccepted()` avec contrôles null-safe pour éviter qu'une erreur JS bloque la redirection.
- Graph Explorer stabilisé : remplacement du layout circulaire par un layout en colonnes défensives.
- Graph Explorer scrollable : les nœuds ne sont plus compactés dans un coin lorsque le graphe contient beaucoup de sous-domaines, IP ou constats.
- Bouton Recentrer corrigé.

## Philosophie inchangée

- Aucun exploit.
- Aucun bruteforce.
- Aucun DoS.
- Nmap reste limité à la détection service/version/port et à la corrélation CVE côté OpenEASM.
