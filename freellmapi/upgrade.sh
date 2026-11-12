#!/usr/bin/env bash
# Back up the FreeLLMAPI data volume, then switch to the given version.
# Usage: ./upgrade.sh [version]   (default v0.16.26)
set -euo pipefail
cd "$(dirname "$0")"
VERSION="${1:-v0.16.26}"

if [ ! -f .env ]; then
  cp .env.example .env
  key=$(openssl rand -hex 32 2>/dev/null || node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
  sed -i.bak "s/^ENCRYPTION_KEY=.*/ENCRYPTION_KEY=$key/" .env && rm -f .env.bak
  echo "Created .env with a new ENCRYPTION_KEY. Keep this file safe."
fi

if [ -n "$(docker compose ps -aq freellmapi)" ]; then
  stamp=$(date +%Y%m%d-%H%M%S)
  echo "Stopping and backing up data to backups/$stamp ..."
  docker compose stop freellmapi
  mkdir -p "backups/$stamp"
  docker compose cp freellmapi:/app/server/data "backups/$stamp/"
  cp .env "backups/$stamp/.env"
fi

if grep -q '^FREELLMAPI_VERSION=' .env; then
  sed -i.bak "s/^FREELLMAPI_VERSION=.*/FREELLMAPI_VERSION=$VERSION/" .env && rm -f .env.bak
else
  echo "FREELLMAPI_VERSION=$VERSION" >> .env
fi

docker compose pull
docker compose up -d
echo "Waiting for health check ..."
for _ in $(seq 1 30); do
  status=$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q freellmapi)" 2>/dev/null || echo starting)
  [ "$status" = healthy ] && { echo "FreeLLMAPI $VERSION is up: http://localhost:${PORT:-3001}"; exit 0; }
  sleep 3
done
echo "Not healthy yet. Check: docker compose logs -f freellmapi" >&2
exit 1
