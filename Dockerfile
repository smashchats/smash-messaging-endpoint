# Build stage
FROM node:22.12-alpine3.20 AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Run stage
FROM node:22.12-alpine3.20

LABEL maintainer="Smashchats <contribute@smashchats.com>"
LABEL description="SMEv1: Implementing the Messaging Endpoint interface of the Smash protocol."
LABEL version="0.0.0-alpha"

ARG PORT=3210
ARG HOST=host.docker.internal
ENV PORT=$PORT \
    HOST=$HOST \
    NODE_ENV=production

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production
RUN npm cache clean --force

# Copy built assets from builder stage
COPY --from=builder --chown=appuser:appgroup /app/dist ./dist

USER appuser

HEALTHCHECK --interval=30s --timeout=3s \
    CMD wget --no-verbose --tries=1 --spider http://localhost:$PORT/health || exit 1

EXPOSE $PORT

CMD ["npm", "start"]
