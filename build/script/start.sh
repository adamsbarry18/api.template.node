#!/bin/bash
set -euo pipefail

echo "==> Starting services (API, MySQL, Redis)..."
docker-compose up -d

# Wait for MySQL to be ready
echo "==> Waiting for MySQL to be available..."
docker-compose exec mysql bash -c 'until mysqladmin ping -h "localhost" --silent; do sleep 1; done'

# Wait for Redis to be ready
echo "==> Waiting for Redis to be available..."
docker-compose exec redis bash -c 'until redis-cli ping; do sleep 1; done'

echo "==> All services are ready!"