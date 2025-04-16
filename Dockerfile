# ---- Base Stage ----
FROM node:18-alpine AS base
WORKDIR /usr/src/app
RUN apt-get update && apt-get install -y dumb-init && rm -rf /var/lib/apt/lists/*

# ---- Dependencies Stage ----
FROM base AS dependencies
COPY package.json package-lock.json* ./
RUN npm ci

# ---- Build Stage ----
FROM base AS build
COPY --from=dependencies /usr/src/app/node_modules ./node_modules
COPY package.json package-lock.json* tsconfig.json ./
COPY src ./src/
RUN npm run build

# ---- Production Stage ----
FROM node:18-alpine AS production
WORKDIR /usr/src/app
ENV NODE_ENV=production
COPY --from=dependencies /usr/src/app/node_modules ./node_modules
COPY --from=build /usr/src/app/dist ./dist
COPY package.json .

EXPOSE 3000

CMD ["dumb-init", "node", "dist/server.js"]