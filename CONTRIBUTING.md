# Contribuer à OpenEASM Alpha

Les contributions sont les bienvenues.

## Règles

- Garder l’outil non intrusif par défaut.
- Ne pas ajouter de scan agressif sans garde-fou.
- Documenter les nouvelles fonctionnalités.
- Tester la compilation Python avant pull request.

## Test rapide

```bash
python -m compileall backend/app
docker-compose up -d --build
```
