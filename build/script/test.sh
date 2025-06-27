#!/bin/bash
set -euo pipefail

echo "==> Running tests inside the API container..."
docker-compose exec api npm run test