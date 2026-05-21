# OpenEASM V7.3 - Graph Explorer, rapport premium et UX juridique

## Correctifs

- Correction de la restauration de l'acceptation juridique : le frontend accepte désormais `accepted=true` renvoyé par `/api/legal/status`.
- Ajout d'un timeout frontend sur `/api/legal/accept-terms` pour éviter un blocage silencieux sur `Enregistrement de l'acceptation...`.
- Amélioration du wording de la carte `Usage responsable`, renommée en verrou juridique validé.

## Rapport PDF

Le PDF a été retravaillé avec :

- une couverture plus professionnelle ;
- des cartes KPI ;
- une synthèse direction ;
- un plan d'action priorisé ;
- une section de cartographie d'exposition ;
- une section Nmap service/version/CVE non exploitante ;
- une page `Portée, limites et responsabilité`.

## Graph Explorer

Nouvel onglet `Graph Explorer`.

Il affiche une cartographie relationnelle des éléments collectés :

- domaine racine ;
- sous-domaines ;
- IP publiques ;
- cibles web ;
- services/ports détectés par Nmap ;
- CVE corrélées ;
- constats priorisés.

Le Graph Explorer ne lance aucun scan supplémentaire. Il visualise uniquement les données produites par l'audit.

## Endpoints ajoutés

- `GET /api/audits/{audit_id}/graph`
- `GET /api/graph/latest`

## Nmap

Aucun changement agressif. La V7.3 conserve le positionnement non exploitant de la V7.2 : service/version/port et corrélation CVE côté OpenEASM.
