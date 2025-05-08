# Użyj oficjalnego obrazu Python jako bazy
FROM python:3.9-slim

# Ustaw katalog roboczy w kontenerze
WORKDIR /app

# Zainstaluj zależności systemowe wymagane przez nmap i potencjalnie scapy
# Zaktualizuj listę pakietów i zainstaluj nmap oraz libpcap-dev (dla scapy)
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

# Skopiuj plik z zależnościami Pythona i zainstaluj je
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Skopiuj resztę plików aplikacji do katalogu roboczego
COPY . .

# Ustaw zmienną środowiskową, aby Flask działał w trybie produkcyjnym (opcjonalnie, dla debugowania można pominąć lub ustawić na 1)
ENV FLASK_ENV=production

# Uruchom aplikację Gunicorn (lub inny serwer WSGI) z Flaskiem
# W tym przykładzie użyjemy prostej komendy pythona, ale w produkcji zaleca się użycie Gunicorn/uWSGI
# CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "network_monitor_backend:app"]
# Alternatywnie, jeśli chcesz uruchomić bezpośrednio z Pythona (np. do celów debugowania):
CMD ["python", "network_monitor_backend.py"]


# Używamy portu 5550 zgodnie z konfiguracją w backendzie
EXPOSE 5550
