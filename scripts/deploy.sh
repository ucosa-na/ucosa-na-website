#!/bin/bash
# Manual deploy helper (mirrors what GitHub Actions does on the droplet)
set -euo pipefail

IMAGE="${DOCKERHUB_USERNAME:-savenbuan}/ucosa-na"
CONTAINER="ucosa-na-app"
APP_DIR="/opt/ucosa-na"

echo "==> Pulling latest image..."
docker pull "$IMAGE:latest"

echo "==> Stopping old container..."
docker stop "$CONTAINER" 2>/dev/null || true
docker rm   "$CONTAINER" 2>/dev/null || true

echo "==> Starting new container..."
docker run -d \
  --name "$CONTAINER" \
  --restart unless-stopped \
  --network app-network \
  -p 3000:3000 \
  --env-file "$APP_DIR/.env" \
  "$IMAGE:latest"

echo "==> Pruning old images..."
docker image prune -f

echo "==> Deployment complete! Container status:"
docker ps --filter "name=$CONTAINER" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
