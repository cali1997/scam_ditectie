# Phishing-detector

Een kleine webapp die berichten controleert op phishing-signalen. De regels staan in `rules.yaml` en de Python-app gebruikt deze om een risicoscore te berekenen.

## Starten met Docker

1. Installeer en start Docker Desktop.
2. Open een terminal in deze map.
3. Voer uit:

```powershell
docker compose up --build
```

Open daarna http://localhost:5000 in je browser.

Stop de app met `Ctrl+C`. Voor het opruimen van de container gebruik je:

```powershell
docker compose down
```

## Bestanden

- `app.py`: Python Flask-webserver en phishing-analyse.
- `rules.yaml`: verdachte patronen, punten en uitleg.
- `compose.yaml`: Docker Compose-configuratie.
- `Dockerfile`: bouwinstructies voor de Python-container.