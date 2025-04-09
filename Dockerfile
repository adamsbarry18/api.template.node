# ---- Base Stage ----
FROM node:18-alpine AS base
# Mettez à jour vers la version LTS de Node que vous utilisez
WORKDIR /usr/src/app
RUN apk update && apk add --no-cache dumb-init # dumb-init pour gérer les signaux correctement

# ---- Dependencies Stage ----
FROM base AS dependencies
COPY package.json package-lock.json* ./
# Installe uniquement les dépendances de production
RUN npm ci --only=production

# ---- Build Stage ----
FROM base AS build
COPY --from=dependencies /usr/src/app/node_modules ./node_modules
COPY package.json package-lock.json* tsconfig.json ./
COPY prisma ./prisma/
COPY src ./src/
# Installe les devDependencies pour build + prisma generate
RUN npm install --only=development
# Génère le client Prisma
RUN npx prisma generate
# Compile le TypeScript
RUN npm run build

# ---- Production Stage ----
FROM base AS production
ENV NODE_ENV=production
COPY --from=dependencies /usr/src/app/node_modules ./node_modules
# Copie le code compilé et les alias résolus
COPY --from=build /usr/src/app/dist ./dist
# Copie le schéma Prisma pour runtime si nécessaire (pas toujours requis)
COPY --from=build /usr/src/app/prisma/schema.prisma ./prisma/schema.prisma
# Copie package.json pour que Node puisse trouver le 'main'
COPY package.json .

# Expose le port
EXPOSE ${PORT:-3000}

# Utilise dumb-init pour démarrer l'application
# Cela assure une gestion correcte des signaux (SIGTERM, SIGINT) pour un arrêt propre
CMD ["dumb-init", "node", "dist/server.js"]