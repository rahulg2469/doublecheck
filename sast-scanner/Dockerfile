# DoubleCheck - SAST scanner image
FROM node:20-alpine

WORKDIR /app

# Install dependencies first (cached unless package files change)
COPY src/package*.json ./
RUN npm ci --omit=dev

# Copy the scanner code
COPY src/ ./

# Run as the built-in non-root "node" user
USER node

ENV NODE_ENV=production
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["npm", "start"]
