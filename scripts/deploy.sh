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
  -v "$APP_DIR/media/Principal_Building_Commissioning:/app/public/Principal_Building_Commissioning" \
  -v "$APP_DIR/media/photo_gallery:/app/public/photo_gallery" \
  -v "$APP_DIR/media/computer_lab:/app/public/computer_lab" \
  -v "$APP_DIR/media/Gala-night:/app/public/Gala-night" \
  -v "$APP_DIR/media/Golden_Jubilee:/app/public/Golden_Jubilee" \
  -v "$APP_DIR/media/Video2:/app/public/Video2" \
  -v "$APP_DIR/media/pic1:/app/public/pic1" \
  -v "$APP_DIR/media/911-Museum:/app/public/911-Museum" \
  -v "$APP_DIR/media/Welcome-night:/app/public/Welcome-night" \
  -v "$APP_DIR/media/Past executives:/app/public/Past executives" \
  -v "$APP_DIR/media/current executive:/app/public/current executive" \
  -v "$APP_DIR/media/ucosa-na-members:/app/public/ucosa-na-members" \
  -v "$APP_DIR/media/ucosa_na_members:/app/public/ucosa_na_members" \
  -v "$APP_DIR/media/Minute_Of_Meetings:/app/public/Minute_Of_Meetings" \
  "$IMAGE:latest"

echo "==> Pruning old images..."
docker image prune -f

echo "==> Deployment complete! Container status:"
docker ps --filter "name=$CONTAINER" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
