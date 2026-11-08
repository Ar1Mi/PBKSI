#!/usr/bin/env bash
# Laboratorium 3 - pełny przebieg od zera:
#   1. czyste kontenery (Keycloak z zaimportowanym realmem, API, aplikacja),
#   2. Authorization Code Flow krok po kroku z wiersza poleceń  -> logs/cli_demo.log
#   3. przejście przez aplikację w Chromium + zrzuty ekranu    -> img/*.png, logs/screenshots.log
#   4. zebranie logów: audyt aplikacji, zdarzenia Keycloaka, ślad back-channel, zawartość bazy sesji
# Wymagania na hoście: docker compose, python3 z pakietami: requests pyjwt cryptography playwright
#   (pip install requests pyjwt cryptography playwright && python3 -m playwright install chromium)
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-python3}

if [ ! -f .env ]; then
  echo "TOKEN_ENC_KEY=$($PY -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" > .env
fi

docker compose down --remove-orphans
rm -rf logs data img/*.png
mkdir -p logs data img
docker compose up -d --build --wait

echo "### Authorization Code Flow z wiersza poleceń"
$PY demo/oauth_cli_demo.py jan jan123 | tee logs/cli_demo.log

echo "### Przeglądarka + zrzuty ekranu"
$PY demo/screenshots.py "$@" | tee logs/screenshots.log

docker compose logs --no-color keycloak | grep -E 'org.keycloak.events' | sed -E 's/^lab3-keycloak +\| //' > logs/keycloak_events.log
echo "Gotowe: logs/audit.log, logs/oauth_trace.log, logs/keycloak_events.log, img/"
