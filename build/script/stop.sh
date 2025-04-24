#!/bin/bash
set -e
echo "==> Arrêt et suppression des containers"
docker-compose down -v