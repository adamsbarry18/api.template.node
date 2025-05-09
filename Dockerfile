# ---- Dependencies (pour dev/test) ----
FROM node:22-alpine AS dependencies
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .

# ---- Builder ----
FROM dependencies AS builder
RUN npm run build

# ---- Production ----
FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV NODE_OPTIONS="--enable-source-maps"
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
EXPOSE 8000
# Utilise dumb-init pour gérer correctement les signaux et éviter les processus zombies
CMD ["dumb-init", "node", "dist/server.js"]