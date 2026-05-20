# OpenEASM V7.5 — Graph Explorer grand format et logo cyborg

## Objectif

Cette version stabilise l’onglet Graph Explorer en l’affichant dans une page plus large afin de mieux visualiser l’ensemble des relations collectées pendant l’audit.

## Nouveautés

- Passage de l’application en **OpenEASM V7.5**.
- Intégration de `cyborg.png` comme nouveau logo officiel de l’application.
- Remplacement des assets `logo.png`, `logo-wide.png`, `logo-192.png`, `logo-512.png`, `favicon.png` et `favicon.ico`.
- Graph Explorer affiché en **grand format** : largeur de page étendue, scène plus haute, colonnes espacées et meilleur confort de lecture.
- Maintien du principe défensif : aucun test supplémentaire n’est lancé depuis l’onglet Graph Explorer ; il affiche uniquement les données déjà collectées par l’audit.

## Philosophie maintenue

OpenEASM V7.5 reste un outil EASM public défensif : détection de surface, service/version/port, corrélation CVE non exploitante, rapports et cartographie relationnelle sans exploitation, sans bruteforce et sans DoS.
