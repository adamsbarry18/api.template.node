#!/bin/bash
# Bash script to ensure a clean DB for each test run (for WSL/Linux)
# Usage: ./test-with-clean-db.sh

# Exit immediately if a command exits with a non-zero status.
set -e

# Stop and remove containers/volumes
printf "[TEST] Stopping and removing containers/volumes...\n"
npm run test-db:stop

# Start containers
printf "[TEST] Starting containers...\n"
npm run test-db:start

# Wait for services to be healthy (optional: adjust if needed)
printf "[TEST] Waiting for services to be healthy...\n"
sleep 5

# Run tests
printf "[TEST] Running tests...\n"
npm run test