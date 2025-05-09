#!/bin/bash
set -e
echo "==> Lancement des tests dans le container API"
docker-compose exec api npm run test