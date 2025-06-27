#!/bin/bash
set -euo pipefail

echo "==> Building the Docker image for the API..."
docker-compose build api