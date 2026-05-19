# OpenEASM V6.0.2

Version corrective de la V6.0.1.

## Corrections

### 1. Audit bloqué par l'export Excel

Erreur corrigée :

```text
ValueError: Cannot convert {'countryName': 'US', 'organizationName': "Let's Encrypt", 'commonName': 'R13'} to Excel
```

Cause : OpenPyXL ne peut pas écrire directement un dictionnaire Python dans une cellule Excel.

Correction : conversion automatique des `dict`, `list`, `tuple`, `set` en texte JSON lisible avant écriture Excel.

### 2. Vérification DNS TXT bloquée

Erreur corrigée :

```text
sqlalchemy.exc.InvalidRequestError: Instance '<VerifiedDomain ...>' is not persistent within this Session
```

Cause : `db.merge(record)` retourne une nouvelle instance persistante qu'il faut réutiliser.

Correction :

```python
record = db.merge(record)
db.commit()
db.refresh(record)
```

### 3. Audit plus robuste

La génération Excel/PDF ne bloque plus complètement le retour JSON de l'audit. Si un export échoue, l'audit peut quand même s'afficher dans l'interface avec l'erreur reportée dans `reports.errors`.

## Installation

```bash
cd ~/openeasm-v6.0.1
docker-compose down

cd ~
unzip openeasm-v6.0.2.zip
cd openeasm-v6.0.2
docker-compose up -d --build
```

Ouvrir :

```text
http://localhost:8000
```

## Vérification

```bash
docker-compose ps
docker-compose logs -f open-easm-api
```
