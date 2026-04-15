# ---- Build Stage ----
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

# ---- Production Stage ----
FROM node:20-alpine AS production
RUN apk add --no-cache postgresql-client
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY . .
RUN chown -R appuser:appgroup /app
USER appuser
ENV NODE_ENV=production
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1
CMD ["node", "src/index.js"]
