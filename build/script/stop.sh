#!/bin/bash
set -euo pipefail

echo "==> Stopping and removing containers and volumes..."
docker-compose down -v