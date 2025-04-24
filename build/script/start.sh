#!/bin/bash
set -e
echo "==> Lancement des services (API, MySQL, Redis)"
docker-compose up -d

echo "==> Attente de la disponibilité de MySQL et Redis..."
docker-compose exec mysql bash -c 'until mysqladmin ping -h "localhost" --silent; do sleep 1; done'
docker-compose exec redis bash -c 'until redis-cli ping | grep PONG; do sleep 1; done'
echo "==> Tous les services sont prêts !"